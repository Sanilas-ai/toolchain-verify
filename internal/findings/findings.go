// Package findings holds the rule/severity report model shared by the
// exec-lint and docker audits. It mirrors agent.Finding so that JSON
// reports of all audits have the same shape.
package findings

import (
	"path/filepath"
	"sort"
	"strings"
)

// Severities.
const (
	SevFail = "fail"
	SevWarn = "warn"
	SevInfo = "info"
)

// Finding is one observation.
type Finding struct {
	Rule     string   `json:"rule"`
	Severity string   `json:"severity"`
	Path     string   `json:"path,omitempty"`
	Line     int      `json:"line,omitempty"`
	Message  string   `json:"message"`
	Fix      string   `json:"fix,omitempty"`
	Refs     []string `json:"refs,omitempty"`
	CWE      []string `json:"cwe,omitempty"`
}

// Location is Path[:Line].
func (f Finding) Location() string {
	if f.Line > 0 {
		return f.Path + ":" + itoa(f.Line)
	}
	return f.Path
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// Collector deduplicates findings and applies ignore entries of the form
// "rule" or "rule:path-glob" ("*" matches any rule; a "/**" suffix matches
// a subtree).
type Collector struct {
	Ignore  []string
	Ignored int
	list    []Finding
	seen    map[string]bool
}

// Add records f unless it is a duplicate or ignored.
func (c *Collector) Add(f Finding) {
	key := f.Rule + "\x00" + f.Path + "\x00" + itoa(f.Line) + "\x00" + f.Message
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	if c.seen[key] {
		return
	}
	c.seen[key] = true
	if Ignored(c.Ignore, f) {
		c.Ignored++
		return
	}
	c.list = append(c.list, f)
}

// Ignored reports whether f matches one of the ignore entries.
func Ignored(ignore []string, f Finding) bool {
	for _, ig := range ignore {
		rule, glob, hasGlob := strings.Cut(ig, ":")
		if rule != f.Rule && rule != "*" {
			continue
		}
		if !hasGlob {
			return true
		}
		if ok, _ := filepath.Match(glob, f.Path); ok {
			return true
		}
		if sub, ok := strings.CutSuffix(glob, "/**"); ok {
			p := filepath.Clean(f.Path)
			if p == filepath.Clean(sub) || strings.HasPrefix(p, filepath.Clean(sub)+"/") {
				return true
			}
		}
	}
	return false
}

// Rank orders severities fail < warn < info.
func Rank(s string) int {
	switch s {
	case SevFail:
		return 0
	case SevWarn:
		return 1
	}
	return 2
}

// Sorted returns the findings ordered by severity, rule, path and line.
func (c *Collector) Sorted() []Finding {
	out := append([]Finding(nil), c.list...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ra, rb := Rank(a.Severity), Rank(b.Severity); ra != rb {
			return ra < rb
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Line < b.Line
	})
	return out
}

// Counts returns the number of findings per severity.
func Counts(fs []Finding) (fail, warn, info int) {
	for _, f := range fs {
		switch f.Severity {
		case SevFail:
			fail++
		case SevWarn:
			warn++
		default:
			info++
		}
	}
	return
}

// OK reports whether no finding fails (or warns, when strict).
func OK(fs []Finding, strict bool) bool {
	fail, warn, _ := Counts(fs)
	return fail == 0 && (!strict || warn == 0)
}
