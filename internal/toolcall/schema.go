package toolcall

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

// ValidateArgs checks args against a JSON Schema object subset:
// type, properties, required, additionalProperties (default false),
// enum, items, minLength/maxLength, minimum/maximum, minItems/maxItems.
// Nesting deeper than maxDepth fails.
func ValidateArgs(schema map[string]interface{}, args map[string]interface{}, maxDepth, maxArgBytes int) error {
	if schema == nil {
		schema = map[string]interface{}{"type": "object", "additionalProperties": false}
	}
	if args == nil {
		args = map[string]interface{}{}
	}
	return validateValue(schema, args, "$", 0, maxDepth, maxArgBytes)
}

func validateValue(schema map[string]interface{}, v interface{}, path string, depth, maxDepth, maxArgBytes int) error {
	if depth > maxDepth {
		return fmt.Errorf("%s: nesting deeper than %d", path, maxDepth)
	}
	if schema == nil {
		return nil
	}
	if enum, ok := schema["enum"].([]interface{}); ok && len(enum) > 0 {
		if !enumContains(enum, v) {
			return fmt.Errorf("%s: value %#v not in enum", path, v)
		}
	}
	typ, _ := schema["type"].(string)
	if typ == "" {
		// infer from keywords
		if _, ok := schema["properties"]; ok {
			typ = "object"
		} else if _, ok := schema["items"]; ok {
			typ = "array"
		}
	}
	switch typ {
	case "", "any":
		return checkSize(path, v, maxArgBytes)
	case "null":
		if v != nil {
			return fmt.Errorf("%s: want null, got %T", path, v)
		}
		return nil
	case "boolean":
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("%s: want boolean, got %T", path, v)
		}
		return nil
	case "string":
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("%s: want string, got %T", path, v)
		}
		if err := checkSize(path, s, maxArgBytes); err != nil {
			return err
		}
		if n, ok := asInt(schema["minLength"]); ok && len([]rune(s)) < n {
			return fmt.Errorf("%s: string shorter than minLength %d", path, n)
		}
		if n, ok := asInt(schema["maxLength"]); ok && len([]rune(s)) > n {
			return fmt.Errorf("%s: string longer than maxLength %d", path, n)
		}
		return nil
	case "number":
		f, ok := asFloat(v)
		if !ok {
			return fmt.Errorf("%s: want number, got %T", path, v)
		}
		if m, ok := asFloat(schema["minimum"]); ok && f < m {
			return fmt.Errorf("%s: %v < minimum %v", path, f, m)
		}
		if m, ok := asFloat(schema["maximum"]); ok && f > m {
			return fmt.Errorf("%s: %v > maximum %v", path, f, m)
		}
		return nil
	case "integer":
		f, ok := asFloat(v)
		if !ok || math.Trunc(f) != f {
			return fmt.Errorf("%s: want integer, got %T", path, v)
		}
		if m, ok := asFloat(schema["minimum"]); ok && f < m {
			return fmt.Errorf("%s: %v < minimum %v", path, f, m)
		}
		if m, ok := asFloat(schema["maximum"]); ok && f > m {
			return fmt.Errorf("%s: %v > maximum %v", path, f, m)
		}
		return nil
	case "array":
		arr, ok := v.([]interface{})
		if !ok {
			return fmt.Errorf("%s: want array, got %T", path, v)
		}
		if n, ok := asInt(schema["minItems"]); ok && len(arr) < n {
			return fmt.Errorf("%s: array shorter than minItems %d", path, n)
		}
		if n, ok := asInt(schema["maxItems"]); ok && len(arr) > n {
			return fmt.Errorf("%s: array longer than maxItems %d", path, n)
		}
		itemSchema, _ := schema["items"].(map[string]interface{})
		for i, it := range arr {
			if err := validateValue(itemSchema, it, fmt.Sprintf("%s[%d]", path, i), depth+1, maxDepth, maxArgBytes); err != nil {
				return err
			}
		}
		return nil
	case "object":
		obj, ok := v.(map[string]interface{})
		if !ok {
			return fmt.Errorf("%s: want object, got %T", path, v)
		}
		props, _ := schema["properties"].(map[string]interface{})
		if props == nil {
			props = map[string]interface{}{}
		}
		addProps := false
		if ap, ok := schema["additionalProperties"]; ok {
			switch t := ap.(type) {
			case bool:
				addProps = t
			case map[string]interface{}:
				addProps = true // schema for additional — treat as allowed + validate
				_ = t
			}
		}
		// default: additionalProperties false
		if _, set := schema["additionalProperties"]; !set {
			addProps = false
		}
		if req, ok := schema["required"].([]interface{}); ok {
			for _, r := range req {
				name, _ := r.(string)
				if name == "" {
					continue
				}
				if _, ok := obj[name]; !ok {
					return fmt.Errorf("%s: missing required %q", path, name)
				}
			}
		}
		for k, val := range obj {
			ps, ok := props[k].(map[string]interface{})
			if !ok {
				if !addProps {
					return fmt.Errorf("%s: additional property %q not allowed", path, k)
				}
				if ap, ok := schema["additionalProperties"].(map[string]interface{}); ok {
					if err := validateValue(ap, val, path+"."+k, depth+1, maxDepth, maxArgBytes); err != nil {
						return err
					}
				} else if err := checkSize(path+"."+k, val, maxArgBytes); err != nil {
					return err
				}
				continue
			}
			if err := validateValue(ps, val, path+"."+k, depth+1, maxDepth, maxArgBytes); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("%s: unsupported schema type %q", path, typ)
	}
}

func checkSize(path string, v interface{}, maxArgBytes int) error {
	if maxArgBytes <= 0 {
		return nil
	}
	switch t := v.(type) {
	case string:
		if len(t) > maxArgBytes {
			return fmt.Errorf("%s: argument larger than %d bytes", path, maxArgBytes)
		}
	default:
		b, err := json.Marshal(v)
		if err == nil && len(b) > maxArgBytes {
			return fmt.Errorf("%s: argument larger than %d bytes", path, maxArgBytes)
		}
	}
	return nil
}

func enumContains(enum []interface{}, v interface{}) bool {
	for _, e := range enum {
		if jsonEqual(e, v) {
			return true
		}
	}
	return false
}

func jsonEqual(a, b interface{}) bool {
	ab, err1 := json.Marshal(a)
	bb, err2 := json.Marshal(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return string(ab) == string(bb)
}

func asFloat(v interface{}) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case float32:
		return float64(t), true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

func asInt(v interface{}) (int, bool) {
	f, ok := asFloat(v)
	if !ok || math.Trunc(f) != f {
		return 0, false
	}
	return int(f), true
}

// SchemaFromJSON parses a JSON Schema object from raw JSON.
func SchemaFromJSON(raw []byte) (map[string]interface{}, error) {
	var m map[string]interface{}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}
