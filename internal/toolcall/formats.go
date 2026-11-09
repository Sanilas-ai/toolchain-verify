package toolcall

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// rawCall is one extracted but not-yet-validated call.
type rawCall struct {
	Name      string
	Arguments map[string]interface{}
	Raw       string
	End       int // byte offset in the (possibly stripped) input after this call
}

var (
	reLFM3Call   = regexp.MustCompile(`(?s)<tool_call>\s*<function=([^>\n]+)>(.*?)</function>\s*</tool_call>`)
	reLFM3Param  = regexp.MustCompile(`(?s)<parameter=([^>\n]+)>\n?(.*?)\n?</parameter>`)
	reMiniFunc   = regexp.MustCompile(`(?s)<function\s+name="([^"]+)">(.*?)</function>`)
	reMiniParam  = regexp.MustCompile(`(?s)<param\s+name="([^"]+)">(.*?)</param>`)
	reHermesCall = regexp.MustCompile(`(?s)<tool_call>\s*(\{.*?\})\s*</tool_call>`)
	reLFM2Block  = regexp.MustCompile(`(?s)<\|tool_call_start\|>(.*?)<\|tool_call_end\|>`)
)

// extractFirst returns the first complete raw call for the profile format,
// the end offset, and whether more content follows after the call.
func extractFirst(format, input string) (rawCall, bool, error) {
	switch format {
	case FormatLFM3XML:
		return extractLFM3(input)
	case FormatMiniCPM5XML:
		return extractMiniCPM5(input)
	case FormatHermesJSON:
		return extractHermes(input)
	case FormatLFM2Pythonic:
		return extractLFM2(input)
	default:
		return rawCall{}, false, fmt.Errorf("unsupported format %q", format)
	}
}

func extractLFM3(input string) (rawCall, bool, error) {
	loc := reLFM3Call.FindStringSubmatchIndex(input)
	if loc == nil {
		if strings.Contains(input, "<tool_call>") && !strings.Contains(input, "</tool_call>") {
			return rawCall{}, false, errTruncated
		}
		return rawCall{}, false, errNoCall
	}
	name := strings.TrimSpace(input[loc[2]:loc[3]])
	body := input[loc[4]:loc[5]]
	args := map[string]interface{}{}
	for _, m := range reLFM3Param.FindAllStringSubmatch(body, -1) {
		args[strings.TrimSpace(m[1])] = coerceScalar(strings.TrimSpace(m[2]))
	}
	rc := rawCall{Name: name, Arguments: args, Raw: input[loc[0]:loc[1]], End: loc[1]}
	return rc, hasTrailing(input, loc[1]), nil
}

func extractMiniCPM5(input string) (rawCall, bool, error) {
	loc := reMiniFunc.FindStringSubmatchIndex(input)
	if loc == nil {
		if strings.Contains(input, "<function") && !strings.Contains(input, "</function>") {
			return rawCall{}, false, errTruncated
		}
		return rawCall{}, false, errNoCall
	}
	name := input[loc[2]:loc[3]]
	body := input[loc[4]:loc[5]]
	args := map[string]interface{}{}
	for _, m := range reMiniParam.FindAllStringSubmatch(body, -1) {
		val := m[2]
		if strings.HasPrefix(val, "<![CDATA[") && strings.HasSuffix(val, "]]>") {
			val = val[len("<![CDATA[") : len(val)-len("]]>")]
		}
		args[m[1]] = coerceScalar(val)
	}
	rc := rawCall{Name: name, Arguments: args, Raw: input[loc[0]:loc[1]], End: loc[1]}
	return rc, hasTrailing(input, loc[1]), nil
}

func extractHermes(input string) (rawCall, bool, error) {
	loc := reHermesCall.FindStringSubmatchIndex(input)
	if loc == nil {
		if strings.Contains(input, "<tool_call>") && !strings.Contains(input, "</tool_call>") {
			return rawCall{}, false, errTruncated
		}
		return rawCall{}, false, errNoCall
	}
	rawJSON := input[loc[2]:loc[3]]
	var obj struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal([]byte(rawJSON), &obj); err != nil {
		return rawCall{}, false, fmt.Errorf("%w: %v", errInvalidJSON, err)
	}
	args := map[string]interface{}{}
	if len(obj.Arguments) > 0 && string(obj.Arguments) != "null" {
		if err := json.Unmarshal(obj.Arguments, &args); err != nil {
			// arguments may itself be a JSON string
			var s string
			if err2 := json.Unmarshal(obj.Arguments, &s); err2 == nil {
				if err3 := json.Unmarshal([]byte(s), &args); err3 != nil {
					return rawCall{}, false, fmt.Errorf("%w: %v", errInvalidJSON, err)
				}
			} else {
				return rawCall{}, false, fmt.Errorf("%w: %v", errInvalidJSON, err)
			}
		}
	}
	if obj.Name == "" {
		return rawCall{}, false, fmt.Errorf("%w: missing name", errInvalidJSON)
	}
	rc := rawCall{Name: obj.Name, Arguments: args, Raw: input[loc[0]:loc[1]], End: loc[1]}
	return rc, hasTrailing(input, loc[1]), nil
}

func extractLFM2(input string) (rawCall, bool, error) {
	loc := reLFM2Block.FindStringSubmatchIndex(input)
	if loc == nil {
		if strings.Contains(input, "<|tool_call_start|>") && !strings.Contains(input, "<|tool_call_end|>") {
			return rawCall{}, false, errTruncated
		}
		return rawCall{}, false, errNoCall
	}
	body := strings.TrimSpace(input[loc[2]:loc[3]])
	// body is a Python list: [fn(a=1), fn2(b="x")] — take the FIRST call only
	calls, err := parsePythonicList(body)
	if err != nil {
		return rawCall{}, false, err
	}
	if len(calls) == 0 {
		return rawCall{}, false, errNoCall
	}
	rc := calls[0]
	rc.Raw = input[loc[0]:loc[1]]
	rc.End = loc[1]
	// trailing junk if more pythonic calls inside the block OR text after end
	trailing := hasTrailing(input, loc[1]) || len(calls) > 1
	return rc, trailing, nil
}

func hasTrailing(input string, end int) bool {
	rest := strings.TrimSpace(input[end:])
	if rest == "" {
		return false
	}
	// ignore a lone im_end / eos
	for _, s := range []string{"<|im_end|>", "<|endoftext|>", "</s>"} {
		rest = strings.TrimSpace(strings.ReplaceAll(rest, s, ""))
	}
	return rest != ""
}

func coerceScalar(s string) interface{} {
	if s == "" {
		return ""
	}
	if s == "true" {
		return true
	}
	if s == "false" {
		return false
	}
	if s == "null" || s == "None" {
		return nil
	}
	if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
		var v interface{}
		if err := json.Unmarshal([]byte(s), &v); err == nil {
			return v
		}
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return float64(i) // JSON numbers are float64 in our maps
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	return s
}

// parsePythonicList parses `[name(arg=..., arg2="x"), ...]` into rawCalls.
// It does NOT eval; only a restricted name/arg grammar is accepted.
func parsePythonicList(s string) ([]rawCall, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errNoCall
	}
	if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
		// single call without brackets
		c, err := parsePythonicCall(s)
		if err != nil {
			return nil, err
		}
		return []rawCall{c}, nil
	}
	inner := strings.TrimSpace(s[1 : len(s)-1])
	if inner == "" {
		return nil, errNoCall
	}
	parts, err := splitTopLevel(inner, ',')
	if err != nil {
		return nil, err
	}
	var out []rawCall
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		c, err := parsePythonicCall(p)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func parsePythonicCall(s string) (rawCall, error) {
	s = strings.TrimSpace(s)
	lp := strings.IndexByte(s, '(')
	if lp <= 0 || !strings.HasSuffix(s, ")") {
		return rawCall{}, fmt.Errorf("%w: not a pythonic call: %q", errParse, trimForErr(s))
	}
	name := strings.TrimSpace(s[:lp])
	if !isIdent(name) {
		return rawCall{}, fmt.Errorf("%w: bad tool name %q", errParse, name)
	}
	inner := s[lp+1 : len(s)-1]
	args := map[string]interface{}{}
	if strings.TrimSpace(inner) != "" {
		kvs, err := splitTopLevel(inner, ',')
		if err != nil {
			return rawCall{}, err
		}
		for _, kv := range kvs {
			kv = strings.TrimSpace(kv)
			if kv == "" {
				continue
			}
			eq := strings.IndexByte(kv, '=')
			if eq <= 0 {
				return rawCall{}, fmt.Errorf("%w: expected name=value in %q", errParse, trimForErr(kv))
			}
			k := strings.TrimSpace(kv[:eq])
			if !isIdent(k) {
				return rawCall{}, fmt.Errorf("%w: bad arg name %q", errParse, k)
			}
			val, err := parsePyValue(strings.TrimSpace(kv[eq+1:]))
			if err != nil {
				return rawCall{}, err
			}
			args[k] = val
		}
	}
	return rawCall{Name: name, Arguments: args}, nil
}

func parsePyValue(s string) (interface{}, error) {
	if s == "True" || s == "true" {
		return true, nil
	}
	if s == "False" || s == "false" {
		return false, nil
	}
	if s == "None" || s == "null" {
		return nil, nil
	}
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return unescapePyString(s[1:len(s)-1], rune(s[0]))
		}
	}
	if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
		// accept JSON subset
		var v interface{}
		if err := json.Unmarshal([]byte(s), &v); err == nil {
			return v, nil
		}
		return nil, fmt.Errorf("%w: complex py value not JSON: %q", errParse, trimForErr(s))
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return float64(i), nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f, nil
	}
	return nil, fmt.Errorf("%w: bad py value %q", errParse, trimForErr(s))
}

func unescapePyString(s string, quote rune) (string, error) {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+1 >= len(s) {
			return "", fmt.Errorf("%w: trailing backslash", errParse)
		}
		switch s[i+1] {
		case '\\', '\'', '"':
			b.WriteByte(s[i+1])
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		default:
			b.WriteByte(s[i+1])
		}
		i++
	}
	return b.String(), nil
}

func splitTopLevel(s string, sep byte) ([]string, error) {
	var parts []string
	depth := 0
	inStr := byte(0)
	esc := false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr != 0 {
			if esc {
				esc = false
				continue
			}
			if c == '\\' {
				esc = true
				continue
			}
			if c == inStr {
				inStr = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			inStr = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("%w: unmatched closer", errParse)
			}
		default:
			if c == sep && depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	if inStr != 0 || depth != 0 {
		return nil, fmt.Errorf("%w: unclosed string or bracket", errParse)
	}
	parts = append(parts, s[start:])
	return parts, nil
}

func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if i == 0 {
			if !(unicode.IsLetter(r) || r == '_') {
				return false
			}
			continue
		}
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

func trimForErr(s string) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}

var (
	errNoCall      = fmt.Errorf("no complete tool call")
	errTruncated   = fmt.Errorf("truncated tool call")
	errInvalidJSON = fmt.Errorf("invalid json")
	errParse       = fmt.Errorf("parse error")
)
