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

// ExecSurface is one exec-capable agent tool surface that contributes to
// policy.require-container: an agent stack that can run code, a stdio MCP
// server (local process), or an approval-bypass setting.
type ExecSurface struct {
	Path string `json:"path"`
	Kind string `json:"kind"` // agent-stack | stdio-mcp | approval-bypass
	Why  string `json:"why"`
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
	// ExecSurfaces lists every exec-capable surface (also mirrored as
	// policy.exec-surface findings for text/JSON/SARIF consumers).
	ExecSurfaces []ExecSurface `json:"exec_surfaces,omitempty"`
	Findings     []Finding     `json:"findings"`
	Ignored      int           `json:"ignored,omitempty"`
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

// SARIF converts findings to SARIF 2.1.0 for GitHub code scanning upload.
// policy.exec-surface findings carry path/kind/why so surfaces appear as
// locations; ExecSurfaces on the JSON report is the structured twin.
func (r *Report) SARIF(version string) any {
	type sarifMessage struct {
		Text string `json:"text"`
	}
	type sarifArtifact struct {
		URI string `json:"uri"`
	}
	type sarifPhysical struct {
		ArtifactLocation sarifArtifact `json:"artifactLocation"`
	}
	type sarifLocation struct {
		PhysicalLocation sarifPhysical `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID    string          `json:"ruleId"`
		Level     string          `json:"level"`
		Message   sarifMessage    `json:"message"`
		Locations []sarifLocation `json:"locations,omitempty"`
	}
	type sarifRule struct {
		ID string `json:"id"`
	}
	type sarifDriver struct {
		Name           string      `json:"name"`
		Version        string      `json:"version,omitempty"`
		InformationURI string      `json:"informationUri"`
		Rules          []sarifRule `json:"rules"`
	}
	type sarifTool struct {
		Driver sarifDriver `json:"driver"`
	}
	type sarifRun struct {
		Tool    sarifTool     `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	type sarifLog struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}

	seen := map[string]bool{}
	var rules []sarifRule
	var res []sarifResult
	for _, f := range r.Findings {
		if !seen[f.Rule] {
			seen[f.Rule] = true
			rules = append(rules, sarifRule{ID: f.Rule})
		}
		lvl := "note"
		switch f.Severity {
		case SevFail:
			lvl = "error"
		case SevWarn:
			lvl = "warning"
		}
		sr := sarifResult{RuleID: f.Rule, Level: lvl, Message: sarifMessage{Text: f.Message}}
		if f.Path != "" {
			sr.Locations = []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: f.Path}}}}
		}
		res = append(res, sr)
	}
	if res == nil {
		res = []sarifResult{}
	}
	if rules == nil {
		rules = []sarifRule{}
	}
	return sarifLog{Schema: "https://json.schemastore.org/sarif-2.1.0.json", Version: "2.1.0",
		Runs: []sarifRun{{Tool: sarifTool{Driver: sarifDriver{Name: "toolchain-verify agent", Version: version,
			InformationURI: "https://github.com/Sanilas-ai/toolchain-verify", Rules: rules}}, Results: res}}}
}
