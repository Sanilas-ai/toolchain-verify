// Package manifest loads and validates toolchain.toml manifests.
package manifest

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/Sanilas-ai/toolchain-verify/internal/agent"
	"github.com/Sanilas-ai/toolchain-verify/internal/dockerhost"
	"github.com/Sanilas-ai/toolchain-verify/internal/execlint"
	"github.com/Sanilas-ai/toolchain-verify/internal/execpolicy"
	"github.com/Sanilas-ai/toolchain-verify/internal/hostsec"
	"github.com/Sanilas-ai/toolchain-verify/internal/models"
	"github.com/Sanilas-ai/toolchain-verify/internal/version"
)

// DefaultFile is the manifest file name used when none is given.
const DefaultFile = "toolchain.toml"

// Manifest is the top-level document.
type Manifest struct {
	// RequireContainer: true = must run inside a container (e.g. the OSS
	// sandbox); false = must run on the host; unset = don't care.
	RequireContainer *bool  `toml:"require_container"`
	Tools            []Tool `toml:"tool"`
	// Agent configures `toolchain-verify agent` (agent-protection checks).
	Agent *agent.Policy `toml:"agent"`
	// ExecLint configures `toolchain-verify exec-lint`.
	ExecLint *execlint.Policy `toml:"exec_lint"`
	// Docker configures `toolchain-verify docker` (host hygiene).
	Docker *dockerhost.Policy `toml:"docker"`
	// Host configures `toolchain-verify host` (apt lag, kernel floors, ufw).
	Host *hostsec.Policy `toml:"host"`
	// ExecPolicy configures `toolchain-verify policy` (host vs sandbox).
	ExecPolicy *execpolicy.Policy `toml:"exec_policy"`
	// Models configures `toolchain-verify models` (model artifact scan).
	Models *models.Policy `toml:"models"`

	// Dir is the directory containing the manifest (not part of the file).
	Dir string `toml:"-"`
}

// Tool describes one expected binary.
type Tool struct {
	Name         string   `toml:"name"`          // display name, unique
	Command      string   `toml:"command"`       // binary name or path; defaults to Name
	Version      string   `toml:"version"`       // constraint, e.g. ">=1.22, <2" or "2.43.0"
	VersionArgs  []string `toml:"version_args"`  // default ["--version"]
	VersionRegex string   `toml:"version_regex"` // optional; group "version" or group 1 is used
	Path         string   `toml:"path"`          // optional glob the binary path must match (** allowed)
	SHA256       string   `toml:"sha256"`        // optional hex digest of the resolved binary
	Optional     bool     `toml:"optional"`      // missing tool is a skip, not a failure

	Constraint *version.Constraint `toml:"-"`
	Regex      *regexp.Regexp      `toml:"-"`
}

var hexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Load reads and validates a manifest. Unknown keys are rejected so that a
// typo (e.g. "sha265") never silently disables a check.
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	m.Dir = filepath.Dir(abs)
	return m, nil
}

// Parse decodes and validates manifest bytes.
func Parse(data []byte) (*Manifest, error) {
	var m Manifest
	md, err := toml.Decode(string(data), &m)
	if err != nil {
		return nil, err
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("unknown keys: %s", strings.Join(keys, ", "))
	}
	if len(m.Tools) == 0 && m.Agent == nil && m.ExecLint == nil && m.Docker == nil && m.Host == nil && m.ExecPolicy == nil && m.Models == nil {
		return nil, fmt.Errorf("no [[tool]] entries and no [agent], [exec_lint], [docker], [host], [exec_policy] or [models] section")
	}
	if m.Agent != nil {
		if err := m.Agent.Validate(); err != nil {
			return nil, err
		}
	}
	if m.ExecLint != nil {
		if err := m.ExecLint.Validate(); err != nil {
			return nil, err
		}
	}
	if m.Docker != nil {
		if err := m.Docker.Validate(); err != nil {
			return nil, err
		}
	}
	if m.Host != nil {
		if err := m.Host.Validate(); err != nil {
			return nil, err
		}
	}
	if m.ExecPolicy != nil {
		if err := m.ExecPolicy.Validate(); err != nil {
			return nil, err
		}
	}
	if err := m.Models.Validate(); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for i := range m.Tools {
		t := &m.Tools[i]
		if t.Name == "" {
			return nil, fmt.Errorf("tool #%d: name is required", i+1)
		}
		if seen[t.Name] {
			return nil, fmt.Errorf("tool %q: duplicate name", t.Name)
		}
		seen[t.Name] = true
		if t.Command == "" {
			t.Command = t.Name
		}
		if len(t.VersionArgs) == 0 {
			t.VersionArgs = []string{"--version"}
		}
		c, err := version.ParseConstraint(t.Version)
		if err != nil {
			return nil, fmt.Errorf("tool %q: %w", t.Name, err)
		}
		t.Constraint = c
		if t.VersionRegex != "" {
			re, err := regexp.Compile(t.VersionRegex)
			if err != nil {
				return nil, fmt.Errorf("tool %q: version_regex: %w", t.Name, err)
			}
			t.Regex = re
		}
		if t.SHA256 != "" {
			t.SHA256 = strings.ToLower(strings.TrimSpace(t.SHA256))
			if !hexRe.MatchString(t.SHA256) {
				return nil, fmt.Errorf("tool %q: sha256 must be 64 hex characters", t.Name)
			}
		}
	}
	return &m, nil
}
