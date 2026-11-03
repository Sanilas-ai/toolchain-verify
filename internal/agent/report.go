package agent

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
	Message  string   `json:"message"`
	Fix      string   `json:"fix,omitempty"`
	Refs     []string `json:"refs,omitempty"`
}

// Install is an agent stack (or blocklisted package) found on disk.
type Install struct {
	Stack      string   `json:"stack,omitempty"`
	Package    string   `json:"package"`
	Version    string   `json:"version"`
	Path       string   `json:"path"`
	Source     string   `json:"source"` // dist-info, node_modules, pnpm, lockfile, requirements, image, docker-image, docker-container, systemd
	Vulnerable []string `json:"vulnerable,omitempty"`
	// Env holds only variables named by an advisory's escalate_env, seen in
	// a container or unit environment. Never serialized.
	Env map[string]string `json:"-"`
}

// Report is the result of an agent run.
type Report struct {
	InContainer  bool      `json:"in_container"`
	Home         string    `json:"home"`
	Cwd          string    `json:"cwd"`
	OK           bool      `json:"ok"`
	Strict       bool      `json:"strict"`
	AdvisoryDB   string    `json:"advisory_db_updated"`
	TrustedRoots []string  `json:"trusted_roots"`
	Scanned      []string  `json:"scanned"`
	Installs     []Install `json:"installs,omitempty"`
	Findings     []Finding `json:"findings"`
	Ignored      int       `json:"ignored,omitempty"`
	// PreSession is set by RunPreSession (cwd-only gate).
	PreSession bool `json:"pre_session,omitempty"`
	// QuarantineDir and Quarantined describe files moved by --quarantine.
	QuarantineDir string             `json:"quarantine_dir,omitempty"`
	Quarantined   []QuarantineAction `json:"quarantined,omitempty"`
}

// Counts returns the number of findings per severity.
func (r *Report) Counts() (fail, warn, info int) {
	for _, f := range r.Findings {
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

type collector struct {
	findings []Finding
	ignore   []string
	ignored  int
	seen     map[string]bool
}

func (c *collector) add(f Finding) {
	key := f.Rule + "\x00" + f.Path + "\x00" + f.Message
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	if c.seen[key] {
		return
	}
	c.seen[key] = true
	for _, ig := range c.ignore {
		rule, glob, hasGlob := strings.Cut(ig, ":")
		if rule != f.Rule && rule != "*" {
			continue
		}
		if !hasGlob {
			c.ignored++
			return
		}
		if ok, _ := filepath.Match(glob, f.Path); ok || (strings.HasSuffix(glob, "/**") && within(f.Path, strings.TrimSuffix(glob, "/**"))) {
			c.ignored++
			return
		}
	}
	c.findings = append(c.findings, f)
}

func sevRank(s string) int {
	switch s {
	case SevFail:
		return 0
	case SevWarn:
		return 1
	}
	return 2
}

func (c *collector) sorted() []Finding {
	out := append([]Finding(nil), c.findings...)
	sortFindings(out)
	return out
}

func sortFindings(out []Finding) {
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := sevRank(out[i].Severity), sevRank(out[j].Severity); a != b {
			return a < b
		}
		if out[i].Rule != out[j].Rule {
			return out[i].Rule < out[j].Rule
		}
		return out[i].Path < out[j].Path
	})
}
