package version

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Constraint is a disjunction ("||") of conjunctions (space/comma separated)
// of comparisons. Supported forms:
//
//	1.22.3        exact
//	1.22 / 1.22.x wildcard (>=1.22.0 <1.23.0)
//	=, ==, !=, >, >=, <, <=
//	~1.2.3        >=1.2.3 <1.3.0
//	^1.2.3        >=1.2.3 <2.0.0 (^0.2.3 -> <0.3.0, ^0.0.3 -> <0.0.4)
//	* / "" / any  any version
type Constraint struct {
	raw  string
	sets [][]comparison
}

type comparison struct {
	op string // "=", "!=", ">", ">=", "<", "<="
	v  Version
}

func (c *Constraint) String() string { return c.raw }

var partialRe = regexp.MustCompile(`^v?(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:-([0-9A-Za-z][0-9A-Za-z.-]*))?(?:\+[0-9A-Za-z.-]+)?$`)

var operators = []string{">=", "<=", "!=", "==", ">", "<", "=", "~", "^"}

// ParseConstraint parses a constraint expression.
func ParseConstraint(s string) (*Constraint, error) {
	c := &Constraint{raw: strings.TrimSpace(s)}
	for _, alt := range strings.Split(s, "||") {
		fields := strings.Fields(strings.ReplaceAll(alt, ",", " "))
		var set []comparison
		for i := 0; i < len(fields); i++ {
			term := fields[i]
			if isOperator(term) { // allow ">= 1.2"
				if i+1 >= len(fields) {
					return nil, fmt.Errorf("constraint %q: operator %q without version", s, term)
				}
				i++
				term += fields[i]
			}
			cmps, err := parseTerm(term)
			if err != nil {
				return nil, fmt.Errorf("constraint %q: %w", s, err)
			}
			set = append(set, cmps...)
		}
		if len(fields) == 0 && len(strings.Split(s, "||")) > 1 {
			return nil, fmt.Errorf("constraint %q: empty alternative", s)
		}
		c.sets = append(c.sets, set)
	}
	return c, nil
}

func isOperator(s string) bool {
	for _, op := range operators {
		if s == op {
			return true
		}
	}
	return false
}

func parseTerm(term string) ([]comparison, error) {
	if strings.EqualFold(term, "any") {
		return nil, nil
	}
	op := ""
	for _, o := range operators {
		if strings.HasPrefix(term, o) {
			op = o
			break
		}
	}
	rest := strings.TrimPrefix(term, op)
	if op == "==" {
		op = "="
	}
	m := partialRe.FindStringSubmatch(rest)
	if m == nil {
		return nil, fmt.Errorf("invalid version %q", rest)
	}
	var nums [3]int
	n := 0 // number of concrete leading components
	wild := false
	for i := 0; i < 3; i++ {
		p := m[i+1]
		if p == "" || p == "x" || p == "X" || p == "*" {
			wild = true
			continue
		}
		if wild {
			return nil, fmt.Errorf("invalid version %q: number after wildcard", rest)
		}
		nums[i], _ = strconv.Atoi(p)
		n++
	}
	v := Version{Major: nums[0], Minor: nums[1], Patch: nums[2], Pre: m[4]}
	if n < 3 && v.Pre != "" {
		return nil, fmt.Errorf("invalid version %q: pre-release needs a full version", rest)
	}
	next := func(level int) Version { // smallest version above the given prefix
		switch level {
		case 1:
			return Version{Major: v.Major + 1}
		case 2:
			return Version{Major: v.Major, Minor: v.Minor + 1}
		default:
			return Version{Major: v.Major, Minor: v.Minor, Patch: v.Patch + 1}
		}
	}
	base := Version{Major: v.Major, Minor: v.Minor, Patch: v.Patch, Pre: v.Pre}

	switch op {
	case "", "=":
		if n == 0 {
			return nil, nil
		}
		if n == 3 {
			return []comparison{{"=", base}}, nil
		}
		return []comparison{{">=", base}, {"<", next(n)}}, nil
	case "!=":
		if n != 3 {
			return nil, fmt.Errorf("!= requires a full version, got %q", rest)
		}
		return []comparison{{"!=", base}}, nil
	case ">":
		if n == 0 {
			return nil, fmt.Errorf("invalid term %q", term)
		}
		if n == 3 {
			return []comparison{{">", base}}, nil
		}
		return []comparison{{">=", next(n)}}, nil
	case ">=":
		return []comparison{{">=", base}}, nil
	case "<":
		if n == 0 {
			return nil, fmt.Errorf("invalid term %q", term)
		}
		return []comparison{{"<", base}}, nil
	case "<=":
		if n == 0 {
			return nil, nil
		}
		if n == 3 {
			return []comparison{{"<=", base}}, nil
		}
		return []comparison{{"<", next(n)}}, nil
	case "~":
		if n == 0 {
			return nil, nil
		}
		if n == 1 {
			return []comparison{{">=", base}, {"<", next(1)}}, nil
		}
		return []comparison{{">=", base}, {"<", next(2)}}, nil
	case "^":
		if n == 0 {
			return nil, nil
		}
		switch {
		case v.Major > 0 || n == 1:
			return []comparison{{">=", base}, {"<", next(1)}}, nil
		case v.Minor > 0 || n == 2:
			return []comparison{{">=", base}, {"<", next(2)}}, nil
		default:
			return []comparison{{">=", base}, {"<", next(3)}}, nil
		}
	}
	return nil, fmt.Errorf("unknown operator in %q", term)
}

// Check reports whether v satisfies the constraint.
func (c *Constraint) Check(v Version) bool {
	for _, set := range c.sets {
		ok := true
		for _, cmp := range set {
			if !cmp.match(v) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func (c comparison) match(v Version) bool {
	r := Compare(v, c.v)
	switch c.op {
	case "=":
		return r == 0
	case "!=":
		return r != 0
	case ">":
		return r > 0
	case ">=":
		return r >= 0
	case "<":
		return r < 0
	case "<=":
		return r <= 0
	}
	return false
}
