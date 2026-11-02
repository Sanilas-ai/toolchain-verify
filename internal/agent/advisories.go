package agent

import (
	_ "embed"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/Sanilas-ai/toolchain-verify/internal/version"
)

//go:embed advisories.toml
var builtinAdvisories []byte

// BuiltinAdvisoryData returns the embedded advisory database (TOML).
func BuiltinAdvisoryData() []byte { return builtinAdvisories }

// Stack is an agent framework to look for.
type Stack struct {
	Name         string   `toml:"name" json:"name"`
	Ecosystem    string   `toml:"ecosystem" json:"ecosystem"`
	Packages     []string `toml:"packages" json:"packages"`
	DockerImages []string `toml:"docker_images" json:"docker_images,omitempty"`
	CanExec      bool     `toml:"can_exec" json:"can_exec"`
	Notes        string   `toml:"notes" json:"notes,omitempty"`
}

// Advisory is one known vulnerability range.
type Advisory struct {
	ID          string   `toml:"id" json:"id"`
	Aliases     []string `toml:"aliases" json:"aliases,omitempty"`
	Stack       string   `toml:"stack" json:"stack"`
	Packages    []string `toml:"packages" json:"packages,omitempty"`
	Affected    string   `toml:"affected" json:"affected"`
	Fixed       string   `toml:"fixed" json:"fixed,omitempty"`
	Severity    string   `toml:"severity" json:"severity"`
	Action      string   `toml:"action" json:"action,omitempty"`
	Condition   string   `toml:"condition" json:"condition,omitempty"`
	EscalateEnv string   `toml:"escalate_env" json:"escalate_env,omitempty"`
	Summary     string   `toml:"summary" json:"summary"`
	Refs        []string `toml:"refs" json:"refs"`

	constraint *version.Constraint
}

// Blocked is a known-malicious package name.
type Blocked struct {
	Ecosystem string   `toml:"ecosystem" json:"ecosystem"`
	Name      string   `toml:"name" json:"name"`
	Reason    string   `toml:"reason" json:"reason"`
	Refs      []string `toml:"refs" json:"refs"`
}

// DB is a merged advisory database.
type DB struct {
	Schema     int        `toml:"schema" json:"schema"`
	Updated    string     `toml:"updated" json:"updated"`
	Stacks     []Stack    `toml:"stack" json:"stacks"`
	Advisories []Advisory `toml:"advisory" json:"advisories"`
	Blocklist  []Blocked  `toml:"blocklist" json:"blocklist,omitempty"`
	Sources    []string   `toml:"-" json:"sources"`
}

var idRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)

// ParseDB decodes and validates one advisory file.
func ParseDB(data []byte, source string) (*DB, error) {
	var db DB
	md, err := toml.Decode(string(data), &db)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("%s: unknown keys: %s", source, strings.Join(keys, ", "))
	}
	if db.Schema != 0 && db.Schema != 1 {
		return nil, fmt.Errorf("%s: unsupported schema %d", source, db.Schema)
	}
	db.Sources = []string{source}
	return &db, nil
}

// Merge appends other into db and re-validates.
func (db *DB) Merge(other *DB) {
	db.Stacks = append(db.Stacks, other.Stacks...)
	db.Advisories = append(db.Advisories, other.Advisories...)
	db.Blocklist = append(db.Blocklist, other.Blocklist...)
	db.Sources = append(db.Sources, other.Sources...)
	if other.Updated > db.Updated {
		db.Updated = other.Updated
	}
}

// Validate checks references and compiles constraints.
func (db *DB) Validate() error {
	stacks := map[string]*Stack{}
	var merged []Stack
	for i, s := range db.Stacks {
		if s.Name == "" || len(s.Packages) == 0 {
			return fmt.Errorf("stack #%d: name and packages are required", i+1)
		}
		if s.Ecosystem != "npm" && s.Ecosystem != "pypi" {
			return fmt.Errorf("stack %q: ecosystem must be npm or pypi", s.Name)
		}
		merged = append(merged, s)
	}
	db.Stacks = nil
	for _, s := range merged {
		if j := db.stackIndex(s.Name); j >= 0 {
			// A later file may extend an existing stack.
			prev := &db.Stacks[j]
			if prev.Ecosystem != s.Ecosystem {
				return fmt.Errorf("stack %q: conflicting ecosystems", s.Name)
			}
			prev.Packages = dedupe(append(prev.Packages, s.Packages...))
			prev.DockerImages = dedupe(append(prev.DockerImages, s.DockerImages...))
			prev.CanExec = prev.CanExec || s.CanExec
			continue
		}
		db.Stacks = append(db.Stacks, s)
	}
	for i := range db.Stacks {
		stacks[db.Stacks[i].Name] = &db.Stacks[i]
	}
	for i := range db.Advisories {
		a := &db.Advisories[i]
		if a.ID == "" || !idRe.MatchString(a.ID) {
			return fmt.Errorf("advisory #%d: invalid id %q", i+1, a.ID)
		}
		s, ok := stacks[a.Stack]
		if !ok {
			return fmt.Errorf("advisory %s: unknown stack %q", a.ID, a.Stack)
		}
		for _, p := range a.Packages {
			if !containsPkg(s.Ecosystem, s.Packages, p) {
				return fmt.Errorf("advisory %s: package %q is not part of stack %q", a.ID, p, a.Stack)
			}
		}
		if strings.TrimSpace(a.Affected) == "" {
			return fmt.Errorf("advisory %s: affected range is required", a.ID)
		}
		c, err := version.ParseConstraint(a.Affected)
		if err != nil {
			return fmt.Errorf("advisory %s: %w", a.ID, err)
		}
		a.constraint = c
		switch a.Action {
		case "":
			a.Action = "fail"
		case "fail", "warn":
		default:
			return fmt.Errorf("advisory %s: action must be fail or warn", a.ID)
		}
		switch a.Severity {
		case "critical", "high", "medium", "low":
		default:
			return fmt.Errorf("advisory %s: severity must be critical/high/medium/low", a.ID)
		}
		if a.EscalateEnv != "" && !strings.Contains(a.EscalateEnv, "=") {
			return fmt.Errorf("advisory %s: escalate_env must be NAME=value", a.ID)
		}
		if len(a.Refs) == 0 {
			return fmt.Errorf("advisory %s: at least one ref (source URL) is required", a.ID)
		}
	}
	for i, b := range db.Blocklist {
		if b.Name == "" || (b.Ecosystem != "npm" && b.Ecosystem != "pypi") {
			return fmt.Errorf("blocklist #%d: name and ecosystem (npm|pypi) are required", i+1)
		}
	}
	return nil
}

func (db *DB) stackIndex(name string) int {
	for i := range db.Stacks {
		if db.Stacks[i].Name == name {
			return i
		}
	}
	return -1
}

// advisoriesFor returns advisories matching ecosystem/package/version.
func (db *DB) advisoriesFor(stack *Stack, pkg string, v version.Version) []*Advisory {
	var out []*Advisory
	for i := range db.Advisories {
		a := &db.Advisories[i]
		if a.Stack != stack.Name {
			continue
		}
		pkgs := a.Packages
		if len(pkgs) == 0 {
			pkgs = stack.Packages
		}
		if !containsPkg(stack.Ecosystem, pkgs, pkg) {
			continue
		}
		if a.constraint.Check(v) {
			out = append(out, a)
		}
	}
	return out
}

// LoadDB loads the built-in database (unless disabled) plus extra files.
func LoadDB(builtin bool, extra []string) (*DB, error) {
	db := &DB{Schema: 1}
	if builtin {
		b, err := ParseDB(builtinAdvisories, "builtin")
		if err != nil {
			return nil, err
		}
		db.Merge(b)
	}
	for _, f := range extra {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		o, err := ParseDB(data, f)
		if err != nil {
			return nil, err
		}
		db.Merge(o)
	}
	if err := db.Validate(); err != nil {
		return nil, err
	}
	return db, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// normPkg normalizes a package name for comparison (PEP 503 for PyPI).
func normPkg(eco, name string) string {
	name = strings.TrimSpace(name)
	if eco == "pypi" {
		return strings.ToLower(pyNormRe.ReplaceAllString(name, "-"))
	}
	return name
}

var pyNormRe = regexp.MustCompile(`[-_.]+`)

func containsPkg(eco string, list []string, name string) bool {
	n := normPkg(eco, name)
	for _, x := range list {
		if normPkg(eco, x) == n {
			return true
		}
	}
	return false
}
