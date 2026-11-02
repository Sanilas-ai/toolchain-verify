// Package execpolicy decides whether a proposed shell command may run on
// the host or only inside a sandbox (e.g. the OSS sandbox via oss-run).
// It is meant for agent pre-exec hooks: the command is parsed, never run.
package execpolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Verdicts.
const (
	Host    = "host"    // may run on the host
	Sandbox = "sandbox" // must run through a sandbox wrapper
	Deny    = "deny"    // must not run (needs a human)
)

// Policy is the [exec_policy] manifest section.
type Policy struct {
	// Default verdict for commands no rule matches (default "host").
	Default string `toml:"default"`
	// SandboxWrappers are command prefixes that run their arguments in the
	// sandbox, e.g. "oss-run", "docker exec oss-sandbox". Words after the
	// first must appear in order among the following arguments.
	SandboxWrappers []string `toml:"sandbox_wrappers"`
	// InSandboxMarkers: when one of these files exists, the checker itself
	// runs inside the sandbox and "sandbox" verdicts are allowed.
	InSandboxMarkers []string `toml:"in_sandbox_markers"`
	// SandboxRoot is the host directory mounted into the sandbox (used for
	// {repo} in SandboxHint), e.g. "~/open-source-polygon".
	SandboxRoot string `toml:"sandbox_root"`
	// SandboxHint is shown for host-forbidden commands; {repo} and
	// {command} are substituted.
	SandboxHint string `toml:"sandbox_hint"`
	// PipeToShell is the verdict for `curl ... | sh` and `sh -c "$(curl ...)"`
	// (default "deny").
	PipeToShell string `toml:"pipe_to_shell"`
	// Unparsable is the verdict for input the parser cannot follow
	// (default "deny": fail closed).
	Unparsable string `toml:"unparsable"`
	Rules      []Rule `toml:"rule"`
}

// Rule maps commands (and optionally argument patterns) to a verdict.
// Rules are evaluated in order; the first match wins.
type Rule struct {
	// Commands are base names or globs ("go", "python3*", "./gradlew").
	Commands []string `toml:"commands"`
	// Args are globs over the space-joined arguments ("install*",
	// "auth refresh*"); empty matches any arguments.
	Args []string `toml:"args"`
	// Where is "host", "sandbox" or "deny".
	Where  string `toml:"where"`
	Reason string `toml:"reason"`
	// Everywhere also applies the rule to commands run through a sandbox
	// wrapper or inside the sandbox (only meaningful with where = "deny").
	Everywhere bool `toml:"everywhere"`
	// Cwd limits the rule to working directories under these paths.
	Cwd []string `toml:"cwd"`
}

func validVerdict(v string) bool { return v == Host || v == Sandbox || v == Deny }

// Validate checks the section.
func (p *Policy) Validate() error {
	for name, v := range map[string]string{"default": p.Default, "pipe_to_shell": p.PipeToShell, "unparsable": p.Unparsable} {
		if v != "" && !validVerdict(v) {
			return fmt.Errorf("exec_policy.%s must be \"host\", \"sandbox\" or \"deny\"", name)
		}
	}
	for i, w := range p.SandboxWrappers {
		if len(strings.Fields(w)) == 0 {
			return fmt.Errorf("exec_policy.sandbox_wrappers #%d is empty", i+1)
		}
	}
	for i, r := range p.Rules {
		where := fmt.Sprintf("exec_policy.rule #%d", i+1)
		if len(r.Commands) == 0 {
			return fmt.Errorf("%s: commands is required", where)
		}
		if !validVerdict(r.Where) {
			return fmt.Errorf("%s: where must be \"host\", \"sandbox\" or \"deny\"", where)
		}
		if r.Everywhere && r.Where != Deny {
			return fmt.Errorf("%s: everywhere = true requires where = \"deny\"", where)
		}
		for _, g := range append(append([]string(nil), r.Commands...), r.Args...) {
			if g == "" {
				return fmt.Errorf("%s: empty pattern", where)
			}
		}
	}
	return nil
}

func (p *Policy) defaults() Policy {
	q := *p
	if q.Default == "" {
		q.Default = Host
	}
	if q.PipeToShell == "" {
		q.PipeToShell = Deny
	}
	if q.Unparsable == "" {
		q.Unparsable = Deny
	}
	if q.InSandboxMarkers == nil {
		q.InSandboxMarkers = []string{"/.dockerenv", "/run/.containerenv"}
	}
	if q.SandboxHint == "" {
		q.SandboxHint = "run it in the sandbox: oss-run -C {repo} {command}"
	}
	return q
}

// expandHome expands a leading "~".
func expandHome(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") && home != "" {
		return filepath.Join(home, p[2:])
	}
	return p
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// wildcard matches s against a pattern where "*" matches any run of
// characters (including "/" and spaces) and "?" one character.
func wildcard(pattern, s string) bool {
	px, sx := 0, 0
	star, mark := -1, 0
	for sx < len(s) {
		switch {
		case px < len(pattern) && (pattern[px] == '?' || pattern[px] == s[sx]):
			px++
			sx++
		case px < len(pattern) && pattern[px] == '*':
			star, mark = px, sx
			px++
		case star >= 0:
			px = star + 1
			mark++
			sx = mark
		default:
			return false
		}
	}
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}
