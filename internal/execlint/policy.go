// Package execlint is a read-only linter that finds places where code
// executes processes or evaluates code in files that also talk to an LLM,
// without routing the call through a hardened container wrapper
// (docker run --network none --read-only --cap-drop ALL --user nobody ...).
package execlint

import (
	"fmt"

	"path/filepath"
	"strings"
)

// Modes.
const (
	ModeReport = "report" // findings are warnings (default)
	ModeFail   = "fail"   // findings fail the run (CI gate)
)

// Policy is the [exec_lint] table of toolchain.toml.
type Policy struct {
	// Paths to scan (files or directories). Default: the working directory.
	Paths []string `toml:"paths"`
	// Exclude subtrees or base-name globs (e.g. "examples/**", "gen_*.py").
	Exclude []string `toml:"exclude"`
	// Wrappers are extra names (commands or functions) that count as a
	// hardened sandbox when they appear around an exec call.
	Wrappers []string `toml:"wrappers"`
	// ExtraLLMMarkers are literal substrings that mark a file as handling
	// LLM output (e.g. an internal client package path).
	ExtraLLMMarkers []string `toml:"extra_llm_markers"`
	// Mode is "report" (default) or "fail".
	Mode string `toml:"mode"`
	// IncludeTests also scans *_test.go, test_*.py, *.spec.ts, ...
	IncludeTests bool `toml:"include_tests"`
	// MaxDepth limits directory recursion (default 12).
	MaxDepth int `toml:"max_depth"`
	// Ignore suppresses findings: "rule" or "rule:path-glob".
	Ignore []string `toml:"ignore"`
	// Strict makes warnings fail.
	Strict bool `toml:"strict"`
}

// Validate checks enum values and ranges.
func (p *Policy) Validate() error {
	switch p.Mode {
	case "", ModeReport, ModeFail:
	default:
		return fmt.Errorf("exec_lint.mode: want %q or %q, got %q", ModeReport, ModeFail, p.Mode)
	}
	if p.MaxDepth < 0 || p.MaxDepth > 64 {
		return fmt.Errorf("exec_lint.max_depth: must be 0..64")
	}
	for _, w := range p.Wrappers {
		if strings.TrimSpace(w) == "" {
			return fmt.Errorf("exec_lint.wrappers: empty name")
		}
	}
	for _, m := range p.ExtraLLMMarkers {
		if len(strings.TrimSpace(m)) < 3 {
			return fmt.Errorf("exec_lint.extra_llm_markers: %q is too short", m)
		}
	}
	return nil
}

// DefaultWrappers are recognised hardened launchers: the sample wrapper
// and Go helper shipped with this repo, the OSS sandbox scripts and common
// sandboxing tools.
var DefaultWrappers = []string{
	"run-isolated", "sandbox.Command", "sandbox.Args",
	"oss-run", "oss-shell", "nsjail", "bwrap", "firejail", "runsc",
}

func expand(p, home, base string) string {
	if p == "~" {
		return home
	}
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		return filepath.Join(home, rest)
	}

	if !filepath.IsAbs(p) && base != "" {
		p = filepath.Join(base, p)
	}
	return filepath.Clean(p)
}
