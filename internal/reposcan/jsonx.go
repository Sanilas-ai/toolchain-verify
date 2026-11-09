package reposcan

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// JSON kinds.
const (
	jObject = iota
	jArray
	jString
	jNumber
	jBool
	jNull
)

// jnode is a JSON value that keeps member order, duplicate keys and line
// numbers. Agent clients disagree on which duplicate wins (first, last or
// error), so the scanner keeps all of them and evaluates every value.
type jnode struct {
	kind    int
	str     string // string value, or raw number / "true" / "false"
	members []jmember
	elems   []*jnode
	line    int
}

type jmember struct {
	key  string
	val  *jnode
	line int
}

// dupKey is a key that occurs more than once in one object.
type dupKey struct {
	key  string
	line int
}

// jsonParser is a small recursive-descent parser for JSON with the JSONC
// extensions that VS Code, Cursor and Zed accept (// and /* */ comments,
// trailing commas). It never allocates more than the input size and refuses
// nesting deeper than maxDepth.
type jsonParser struct {
	b        []byte
	i        int
	line     int
	depth    int
	maxDepth int
	dups     []dupKey
}

const jsonMaxDepth = 64

// parseJSONC parses b. Duplicate keys are returned separately; they are not
// an error.
func parseJSONC(b []byte) (*jnode, []dupKey, error) {
	if !utf8.Valid(b) {
		return nil, nil, fmt.Errorf("invalid UTF-8")
	}
	p := &jsonParser{b: b, line: 1, maxDepth: jsonMaxDepth}
	// UTF-8 BOM is tolerated by every client we care about.
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		p.i = 3
	}
	if err := p.ws(); err != nil {
		return nil, nil, err
	}
	n, err := p.value()
	if err != nil {
		return nil, p.dups, err
	}
	if err := p.ws(); err != nil {
		return nil, p.dups, err
	}
	if p.i != len(p.b) {
		return nil, p.dups, p.errf("trailing data after top-level value")
	}
	return n, p.dups, nil
}

func (p *jsonParser) errf(format string, a ...any) error {
	return fmt.Errorf("line %d: %s", p.line, fmt.Sprintf(format, a...))
}

// ws skips whitespace and comments.
func (p *jsonParser) ws() error {
	for p.i < len(p.b) {
		c := p.b[p.i]
		switch {
		case c == '\n':
			p.line++
			p.i++
		case c == ' ' || c == '\t' || c == '\r':
			p.i++
		case c == '/' && p.i+1 < len(p.b) && p.b[p.i+1] == '/':
			for p.i < len(p.b) && p.b[p.i] != '\n' {
				p.i++
			}
		case c == '/' && p.i+1 < len(p.b) && p.b[p.i+1] == '*':
			p.i += 2
			closed := false
			for p.i+1 < len(p.b) {
				if p.b[p.i] == '\n' {
					p.line++
				}
				if p.b[p.i] == '*' && p.b[p.i+1] == '/' {
					p.i += 2
					closed = true
					break
				}
				p.i++
			}
			if !closed {
				return p.errf("unterminated comment")
			}
		default:
			return nil
		}
	}
	return nil
}

func (p *jsonParser) value() (*jnode, error) {
	if p.i >= len(p.b) {
		return nil, p.errf("unexpected end of input")
	}
	line := p.line
	switch c := p.b[p.i]; {
	case c == '{':
		return p.object()
	case c == '[':
		return p.array()
	case c == '"':
		s, err := p.str()
		if err != nil {
			return nil, err
		}
		return &jnode{kind: jString, str: s, line: line}, nil
	case c == 't' || c == 'f' || c == 'n':
		for _, lit := range []string{"true", "false", "null"} {
			if strings.HasPrefix(string(p.b[p.i:min(len(p.b), p.i+5)]), lit) {
				p.i += len(lit)
				if lit == "null" {
					return &jnode{kind: jNull, line: line}, nil
				}
				return &jnode{kind: jBool, str: lit, line: line}, nil
			}
		}
		return nil, p.errf("invalid literal")
	case c == '-' || (c >= '0' && c <= '9'):
		start := p.i
		for p.i < len(p.b) && strings.IndexByte("+-0123456789.eE", p.b[p.i]) >= 0 {
			p.i++
		}
		raw := string(p.b[start:p.i])
		if _, err := strconv.ParseFloat(raw, 64); err != nil {
			return nil, p.errf("invalid number %q", raw)
		}
		return &jnode{kind: jNumber, str: raw, line: line}, nil
	}
	return nil, p.errf("unexpected character %q", p.b[p.i])
}

func (p *jsonParser) enter() error {
	p.depth++
	if p.depth > p.maxDepth {
		return p.errf("nesting deeper than %d", p.maxDepth)
	}
	return nil
}

func (p *jsonParser) object() (*jnode, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer func() { p.depth-- }()
	n := &jnode{kind: jObject, line: p.line}
	p.i++ // {
	seen := map[string]bool{}
	for {
		if err := p.ws(); err != nil {
			return nil, err
		}
		if p.i >= len(p.b) {
			return nil, p.errf("unterminated object")
		}
		if p.b[p.i] == '}' {
			p.i++
			return n, nil
		}
		if p.b[p.i] != '"' {
			return nil, p.errf("expected object key")
		}
		kline := p.line
		k, err := p.str()
		if err != nil {
			return nil, err
		}
		if seen[k] {
			p.dups = append(p.dups, dupKey{key: k, line: kline})
		}
		seen[k] = true
		if err := p.ws(); err != nil {
			return nil, err
		}
		if p.i >= len(p.b) || p.b[p.i] != ':' {
			return nil, p.errf("expected ':' after key")
		}
		p.i++
		if err := p.ws(); err != nil {
			return nil, err
		}
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		n.members = append(n.members, jmember{key: k, val: v, line: kline})
		if err := p.ws(); err != nil {
			return nil, err
		}
		if p.i < len(p.b) && p.b[p.i] == ',' {
			p.i++
			continue
		}
		if p.i < len(p.b) && p.b[p.i] == '}' {
			continue
		}
		return nil, p.errf("expected ',' or '}'")
	}
}

func (p *jsonParser) array() (*jnode, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer func() { p.depth-- }()
	n := &jnode{kind: jArray, line: p.line}
	p.i++
	for {
		if err := p.ws(); err != nil {
			return nil, err
		}
		if p.i >= len(p.b) {
			return nil, p.errf("unterminated array")
		}
		if p.b[p.i] == ']' {
			p.i++
			return n, nil
		}
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		n.elems = append(n.elems, v)
		if err := p.ws(); err != nil {
			return nil, err
		}
		if p.i < len(p.b) && p.b[p.i] == ',' {
			p.i++
			continue
		}
		if p.i < len(p.b) && p.b[p.i] == ']' {
			continue
		}
		return nil, p.errf("expected ',' or ']'")
	}
}

// str parses a JSON string and decodes escapes (including \uXXXX surrogate
// pairs), so that "\u0069gnore" is seen as "ignore".
func (p *jsonParser) str() (string, error) {
	p.i++ // opening quote
	var sb strings.Builder
	for p.i < len(p.b) {
		c := p.b[p.i]
		switch {
		case c == '"':
			p.i++
			return sb.String(), nil
		case c == '\n':
			return "", p.errf("newline in string")
		case c == '\\':
			if p.i+1 >= len(p.b) {
				return "", p.errf("bad escape")
			}
			e := p.b[p.i+1]
			p.i += 2
			switch e {
			case '"', '\\', '/':
				sb.WriteByte(e)
			case 'b':
				sb.WriteByte('\b')
			case 'f':
				sb.WriteByte('\f')
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			case 't':
				sb.WriteByte('\t')
			case 'u':
				r, ok := p.hex4()
				if !ok {
					return "", p.errf("bad \\u escape")
				}
				if utf16.IsSurrogate(r) && p.i+1 < len(p.b) && p.b[p.i] == '\\' && p.b[p.i+1] == 'u' {
					save := p.i
					p.i += 2
					if r2, ok := p.hex4(); ok {
						if d := utf16.DecodeRune(r, r2); d != utf8.RuneError {
							sb.WriteRune(d)
							continue
						}
					}
					p.i = save
				}
				sb.WriteRune(r)
			default:
				return "", p.errf("bad escape \\%c", e)
			}
		default:
			sb.WriteByte(c)
			p.i++
		}
	}
	return "", p.errf("unterminated string")
}

func (p *jsonParser) hex4() (rune, bool) {
	if p.i+4 > len(p.b) {
		return 0, false
	}
	v, err := strconv.ParseUint(string(p.b[p.i:p.i+4]), 16, 32)
	if err != nil {
		return 0, false
	}
	p.i += 4
	return rune(v), true
}

// get returns every value stored under key (case-insensitive when fold is
// set), keeping duplicates.
func (n *jnode) get(key string, fold bool) []*jnode {
	if n == nil || n.kind != jObject {
		return nil
	}
	var out []*jnode
	for _, m := range n.members {
		if m.key == key || (fold && strings.EqualFold(m.key, key)) {
			out = append(out, m.val)
		}
	}
	return out
}

// strs collects string values of n (a string or an array of strings).
func (n *jnode) strs() []string {
	if n == nil {
		return nil
	}
	switch n.kind {
	case jString:
		return []string{n.str}
	case jArray:
		var out []string
		for _, e := range n.elems {
			if e.kind == jString {
				out = append(out, e.str)
			}
		}
		return out
	}
	return nil
}

// truthy reports a JSON true or the strings "true"/"on"/"always".
func (n *jnode) truthy() bool {
	if n == nil {
		return false
	}
	switch n.kind {
	case jBool:
		return n.str == "true"
	case jString:
		s := strings.ToLower(n.str)
		return s == "true" || s == "on" || s == "always" || s == "yes"
	case jArray:
		return len(n.elems) > 0
	case jObject:
		return len(n.members) > 0
	}
	return false
}

// walkStrings visits every string value below n with the key path that
// leads to it.
func (n *jnode) walkStrings(path []string, visit func(path []string, s *jnode)) {
	if n == nil {
		return
	}
	switch n.kind {
	case jString:
		visit(path, n)
	case jObject:
		for _, m := range n.members {
			n2 := append(append([]string(nil), path...), m.key)
			m.val.walkStrings(n2, visit)
		}
	case jArray:
		for _, e := range n.elems {
			e.walkStrings(path, visit)
		}
	}
}
