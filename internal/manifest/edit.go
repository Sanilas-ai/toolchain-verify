package manifest

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
)

// ToolEdit sets string keys on the Index-th [[tool]] entry of a manifest.
type ToolEdit struct {
	Index int
	Set   map[string]string
}

// editKeyOrder is the order in which missing keys are appended to a block.
var editKeyOrder = map[string]int{"version": 0, "path": 1, "sha256": 2}

// EditTools rewrites string keys of [[tool]] entries in place and returns the
// new document. Everything else (comments, key order, other sections,
// formatting of untouched lines) is preserved byte for byte. An existing key
// line is replaced (its trailing comment is kept); a missing key is inserted
// after the last key of the entry.
//
// The result is decoded again and compared with the original document plus
// the requested changes; any other difference is an error, so a layout the
// line editor does not understand can never silently corrupt a manifest.
func EditTools(data []byte, edits []ToolEdit) ([]byte, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("manifest is not valid UTF-8")
	}
	var before map[string]any
	if _, err := toml.Decode(string(data), &before); err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	blocks, err := scanToolBlocks(lines)
	if err != nil {
		return nil, err
	}
	rawTools, isTables := before["tool"].([]map[string]any)
	if _, present := before["tool"]; (present && !isTables) || len(blocks) != len(rawTools) {
		return nil, fmt.Errorf("found %d [[tool]] headers but %d tool entries; only the [[tool]] table form can be edited", len(blocks), len(rawTools))
	}

	replace := map[int]replacement{} // start line -> replacement
	insert := map[int][]string{}     // after line -> new lines
	for _, e := range edits {
		if e.Index < 0 || e.Index >= len(blocks) {
			return nil, fmt.Errorf("tool index %d out of range", e.Index)
		}
		b := blocks[e.Index]
		keys := make([]string, 0, len(e.Set))
		for k := range e.Set {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			oi, iok := editKeyOrder[keys[i]]
			oj, jok := editKeyOrder[keys[j]]
			if iok != jok {
				return iok
			}
			if oi != oj {
				return oi < oj
			}
			return keys[i] < keys[j]
		})
		for _, k := range keys {
			if !isBareKey(k) {
				return nil, fmt.Errorf("cannot edit key %q", k)
			}
			val, err := tomlString(e.Set[k])
			if err != nil {
				return nil, fmt.Errorf("tool #%d %s: %w", e.Index+1, k, err)
			}
			if kv, ok := b.keys[k]; ok {
				first := strings.TrimSuffix(lines[kv.start], "\r")
				nl := first[:kv.eq+1] + " " + val
				if kv.comment != "" {
					nl += " " + kv.comment
				}
				if strings.HasSuffix(lines[kv.end], "\r") {
					nl += "\r"
				}
				replace[kv.start] = replacement{end: kv.end, line: nl}
				continue
			}
			nl := b.indent + k + " = " + val
			if strings.HasSuffix(lines[b.last], "\r") {
				nl += "\r"
			}
			insert[b.last] = append(insert[b.last], nl)
		}
	}

	out := make([]string, 0, len(lines)+len(insert))
	for i := 0; i < len(lines); i++ {
		if r, ok := replace[i]; ok {
			out = append(out, r.line)
			for j := i + 1; j <= r.end; j++ {
				out = append(out, insert[j]...) // never a key end inside a span, but keep any
			}
			i = r.end
		} else {
			out = append(out, lines[i])
		}
		out = append(out, insert[i]...)
	}
	res := []byte(strings.Join(out, "\n"))

	var after map[string]any
	if _, err := toml.Decode(string(res), &after); err != nil {
		return nil, fmt.Errorf("internal: edited manifest does not parse: %w", err)
	}
	for _, e := range edits {
		for k, v := range e.Set {
			rawTools[e.Index][k] = v
		}
	}
	if !reflect.DeepEqual(before, after) {
		return nil, fmt.Errorf("internal: edit would change more than the requested keys; manifest left untouched")
	}
	return res, nil
}

type replacement struct {
	end  int
	line string
}

type keySpan struct {
	start, end int    // first and last line of the key/value pair
	eq         int    // byte offset of '=' on the start line
	comment    string // trailing comment on the end line ("" if none)
}

type toolBlock struct {
	last   int // last line of the last key/value pair (or the header line)
	indent string
	keys   map[string]keySpan
}

// scanState tracks multi-line constructs across lines.
type scanState struct {
	ml    string // open multi-line string delimiter (`"""` or `'''`)
	depth int    // open [ / { inside a value
}

func (s scanState) clean() bool { return s.ml == "" && s.depth == 0 }

// scanToolBlocks finds every [[tool]] header and the key/value pairs that
// belong to it.
func scanToolBlocks(lines []string) ([]*toolBlock, error) {
	var blocks []*toolBlock
	var cur *toolBlock
	var st scanState
	var pending *keySpan
	var pendingKey string
	for i, raw := range lines {
		line := strings.TrimSuffix(raw, "\r")
		if !st.clean() {
			c := scanValue(line, 0, &st)
			if st.clean() && pending != nil {
				pending.end = i
				pending.comment = comment(line, c)
				if cur != nil {
					cur.keys[pendingKey] = *pending
					cur.last = i
				}
				pending = nil
			}
			continue
		}
		t := strings.TrimSpace(line)
		switch {
		case t == "" || strings.HasPrefix(t, "#"):
			continue
		case strings.HasPrefix(t, "[["):
			end := strings.Index(t, "]]")
			if end < 0 {
				return nil, fmt.Errorf("line %d: malformed table header", i+1)
			}
			if unquoteKey(strings.TrimSpace(t[2:end])) == "tool" {
				cur = &toolBlock{last: i, keys: map[string]keySpan{}}
				blocks = append(blocks, cur)
			} else {
				cur = nil
			}
			continue
		case strings.HasPrefix(t, "["):
			cur = nil
			continue
		}
		eq := keyEnd(line)
		if eq < 0 {
			return nil, fmt.Errorf("line %d: cannot parse key/value", i+1)
		}
		key := unquoteKey(strings.TrimSpace(line[:eq]))
		kv := keySpan{start: i, end: i, eq: eq}
		c := scanValue(line, eq+1, &st)
		if cur != nil && len(cur.keys) == 0 {
			cur.indent = line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		}
		if !st.clean() {
			pending, pendingKey = &kv, key
			if cur != nil {
				cur.keys[key] = kv // placeholder so the indent logic sees a key
			}
			continue
		}
		kv.comment = comment(line, c)
		if cur != nil {
			cur.keys[key] = kv
			cur.last = i
		}
	}
	if !st.clean() {
		return nil, fmt.Errorf("unterminated multi-line value")
	}
	return blocks, nil
}

func comment(line string, at int) string {
	if at < 0 {
		return ""
	}
	return strings.TrimRight(line[at:], " \t")
}

// keyEnd returns the offset of the '=' that ends the key on a line.
func keyEnd(line string) int {
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '=':
			return i
		case '"', '\'':
			q := line[i]
			for i++; i < len(line) && line[i] != q; i++ {
				if q == '"' && line[i] == '\\' {
					i++
				}
			}
		case '#':
			return -1
		}
	}
	return -1
}

// scanValue advances st over line[from:] and returns the offset of a trailing
// comment, or -1.
func scanValue(line string, from int, st *scanState) int {
	for i := from; i < len(line); i++ {
		if st.ml != "" {
			if st.ml == `"""` && line[i] == '\\' {
				i++
				continue
			}
			if strings.HasPrefix(line[i:], st.ml) {
				i += 2
				// up to two extra quotes may close the string ("""a"""")
				for k := 0; k < 2 && i+1 < len(line) && line[i+1] == st.ml[0]; k++ {
					i++
				}
				st.ml = ""
			}
			continue
		}
		switch c := line[i]; c {
		case '#':
			return i
		case '"', '\'':
			delim := strings.Repeat(string(c), 3)
			if strings.HasPrefix(line[i:], delim) {
				st.ml = delim
				i += 2
				continue
			}
			for i++; i < len(line) && line[i] != c; i++ {
				if c == '"' && line[i] == '\\' {
					i++
				}
			}
		case '[', '{':
			st.depth++
		case ']', '}':
			if st.depth > 0 {
				st.depth--
			}
		}
	}
	return -1
}

func unquoteKey(k string) string {
	if len(k) >= 2 && (k[0] == '"' || k[0] == '\'') && k[len(k)-1] == k[0] && !strings.Contains(k, `\`) {
		return k[1 : len(k)-1]
	}
	return k
}

func isBareKey(k string) bool {
	if k == "" {
		return false
	}
	for _, r := range k {
		if !(r == '_' || r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// tomlString encodes s as a TOML basic string.
func tomlString(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("value is not valid UTF-8")
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String(), nil
}
