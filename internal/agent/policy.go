// Package agent implements `toolchain-verify agent`: read-only checks that
// protect AI coding agents (and the machine they run on) against practical,
// documented threat classes: planted instruction files, vulnerable agent
// stacks, risky MCP/tool configuration, credential exposure and a few
// supply-chain footguns. It never executes binaries and never opens
// credential files (it only stats them).
package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Policy is the [agent] table of a toolchain.toml manifest. Every field is
// optional; zero values select safe defaults (see Defaults).
type Policy struct {
	// TrustedRoots are directories whose instruction files (AGENTS.md, ...)
	// are trusted project instructions, e.g. ["~/open-source-polygon"].
	TrustedRoots []string `toml:"trusted_roots"`
	// UntrustedDirs are scanned for planted instruction files and agent
	// configs. Default: Downloads (incl. XDG/localized), Desktop, /tmp,
	// /var/tmp, /dev/shm.
	UntrustedDirs []string `toml:"untrusted_dirs"`
	// ExtraUntrustedDirs are appended to the (default or explicit) list.
	ExtraUntrustedDirs []string `toml:"extra_untrusted_dirs"`
	// InstructionFiles overrides the list of instruction file patterns.
	// A pattern without "/" matches a base name; with "/" it matches the
	// trailing path segments (e.g. ".github/copilot-instructions.md").
	InstructionFiles []string `toml:"instruction_files"`
	// ExtraInstructionFiles are appended to the default patterns.
	ExtraInstructionFiles []string `toml:"extra_instruction_files"`
	// UntrustedInstruction is "fail" (default) or "warn".
	UntrustedInstruction string `toml:"untrusted_instruction"`
	// ScanDepth limits directory recursion for instruction scans (default 4).
	ScanDepth int `toml:"scan_depth"`
	// ForbidCwd: running an agent (or this tool) with a working directory
	// inside one of these is a failure. Default: the untrusted dirs.
	ForbidCwd []string `toml:"forbid_cwd"`
	// InventoryPaths are searched for installed agent stacks (site-packages,
	// node_modules, lockfiles, compose files). Default: trusted roots plus
	// common global install locations.
	InventoryPaths []string `toml:"inventory_paths"`
	// ExtraInventoryPaths are appended to the (default or explicit) list.
	ExtraInventoryPaths []string `toml:"extra_inventory_paths"`
	// InventoryDepth limits recursion for the inventory walk (default 6).
	InventoryDepth int `toml:"inventory_depth"`
	// Advisories are extra advisory database files (TOML), relative to the
	// manifest directory. They are merged with the built-in database.
	Advisories []string `toml:"advisories"`
	// BuiltinAdvisories=false disables the embedded advisory database.
	BuiltinAdvisories *bool `toml:"builtin_advisories"`
	// MCPConfigs are extra MCP / agent config files to audit.
	MCPConfigs []string `toml:"mcp_configs"`
	// RequireContainerForExec (default true): an exec-capable agent stack
	// (Flowise, Langflow, PraisonAI, ...) installed outside a container is a
	// failure.
	RequireContainerForExec *bool `toml:"require_container_for_exec"`
	// CredentialPaths are extra credential files/dirs (never opened, only
	// stat'ed; scanning into them is refused).
	CredentialPaths []string `toml:"credential_paths"`
	// SupplyChain (default true) enables index/registry, pickle-model and
	// .pth startup-hook checks.
	SupplyChain *bool `toml:"supply_chain"`
	// Strict makes warnings fail the run.
	Strict bool `toml:"strict"`
	// Ignore suppresses findings: entries are "rule" or "rule:path-glob".
	Ignore []string `toml:"ignore"`
}

// DefaultInstructionFiles are the instruction/rules files that coding agents
// load automatically from the working directory (and often its parents).
var DefaultInstructionFiles = []string{
	"AGENTS.md", "AGENTS.override.md", // Codex, many others
	"CLAUDE.md", "CLAUDE.local.md", // Claude Code
	"GEMINI.md",                       // Gemini CLI
	".cursorrules", ".cursor/rules/*", // Cursor
	".windsurfrules", ".windsurf/rules/*", // Windsurf
	".clinerules", ".clinerules/*", // Cline
	".roorules", ".roo/rules/*", // Roo Code
	".github/copilot-instructions.md", ".github/instructions/*.instructions.md", // Copilot
	".junie/guidelines.md", // JetBrains Junie
}

// Defaults returns the default untrusted directories for home.
func DefaultUntrustedDirs(home string) []string {
	dirs := []string{
		filepath.Join(home, "Downloads"),
		filepath.Join(home, "Загрузки"),
		filepath.Join(home, "Desktop"),
		filepath.Join(home, "Рабочий стол"),
		"/tmp", "/var/tmp", "/dev/shm",
	}
	if x := xdgDownloadDir(home); x != "" {
		dirs = append(dirs, x)
	}
	return dedupe(dirs)
}

// DefaultInventoryPaths returns global install locations searched for agent
// stacks in addition to the trusted roots.
func DefaultInventoryPaths(home string) []string {
	return []string{
		filepath.Join(home, ".local", "lib"),
		filepath.Join(home, ".local", "share", "pipx", "venvs"),
		filepath.Join(home, ".local", "share", "uv", "tools"),
		filepath.Join(home, ".npm-global"),
		filepath.Join(home, ".nvm", "versions", "node"),
		filepath.Join(home, ".venv"),
		"/usr/local/lib",
		"/usr/lib/python3",
		"/usr/lib/node_modules",
		"/opt",
	}
}

// CredentialDirs are never descended into by any walk.
func CredentialDirs(home string) []string {
	rel := []string{
		".ssh", ".gnupg", ".aws", ".azure", ".codex", ".claude", ".gemini",
		".config/gh", ".config/gcloud", ".config/github-copilot", ".docker", ".kube",
		".local/share/keyrings", ".password-store", ".mozilla",
		".config/google-chrome", ".config/chromium", ".config/BraveSoftware",
		".config/Cursor/User/globalStorage", ".config/Code/User/globalStorage",
	}
	out := make([]string, len(rel))
	for i, r := range rel {
		out[i] = filepath.Join(home, filepath.FromSlash(r))
	}
	return out
}

// CredentialFiles are token/key files that are stat'ed (permissions) but
// never opened. Entries may contain a glob in the last element.
func CredentialFiles(home string) []string {
	rel := []string{
		".git-credentials", ".netrc", ".npmrc", ".pypirc", ".yarnrc.yml",
		".codex/auth.json", ".claude/.credentials.json", ".gemini/oauth_creds.json",
		".config/gh/hosts.yml", ".config/github-copilot/hosts.json", ".config/github-copilot/apps.json",
		".aws/credentials", ".docker/config.json", ".kube/config",
		".config/gcloud/application_default_credentials.json", ".config/gcloud/credentials.db",
		".ssh/id_*",
	}
	out := make([]string, len(rel))
	for i, r := range rel {
		out[i] = filepath.Join(home, filepath.FromSlash(r))
	}
	return out
}

func xdgDownloadDir(home string) string {
	b, err := os.ReadFile(filepath.Join(home, ".config", "user-dirs.dirs"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "XDG_DOWNLOAD_DIR="); ok {
			v = strings.Trim(v, `"`)
			v = strings.ReplaceAll(v, "$HOME", home)
			if filepath.IsAbs(v) && filepath.Clean(v) != filepath.Clean(home) {
				return filepath.Clean(v)
			}
		}
	}
	return ""
}

// Validate checks enum values and obviously wrong settings.
func (p *Policy) Validate() error {
	switch p.UntrustedInstruction {
	case "", "fail", "warn":
	default:
		return fmt.Errorf("agent.untrusted_instruction must be \"fail\" or \"warn\", got %q", p.UntrustedInstruction)
	}
	if p.ScanDepth < 0 || p.ScanDepth > 32 {
		return fmt.Errorf("agent.scan_depth must be 0..32")
	}
	if p.InventoryDepth < 0 || p.InventoryDepth > 32 {
		return fmt.Errorf("agent.inventory_depth must be 0..32")
	}
	for _, ig := range p.Ignore {
		rule, glob, _ := strings.Cut(ig, ":")
		if rule == "" {
			return fmt.Errorf("agent.ignore: empty rule in %q", ig)
		}
		if glob != "" {
			if _, err := filepath.Match(glob, "x"); err != nil {
				return fmt.Errorf("agent.ignore %q: %w", ig, err)
			}
		}
	}
	return nil
}

func boolOr(b *bool, def bool) bool {
	if b == nil {
		return def
	}
	return *b
}

// expand resolves "~", "$HOME" and relative paths (against base).
func expand(p, home, base string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	switch {
	case p == "~":
		p = home
	case strings.HasPrefix(p, "~/"):
		p = filepath.Join(home, p[2:])
	case strings.HasPrefix(p, "$HOME"):
		p = home + p[len("$HOME"):]
	}
	if !filepath.IsAbs(p) && base != "" {
		p = filepath.Join(base, p)
	}
	return filepath.Clean(p)
}

func expandAll(ps []string, home, base string) []string {
	var out []string
	for _, p := range ps {
		if e := expand(p, home, base); e != "" {
			out = append(out, e)
		}
	}
	return dedupe(out)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// within reports whether p is dir or inside dir (lexically, after Clean).
func within(p, dir string) bool {
	p, dir = filepath.Clean(p), filepath.Clean(dir)
	if p == dir {
		return true
	}
	if dir == string(filepath.Separator) {
		return true
	}
	return strings.HasPrefix(p, dir+string(filepath.Separator))
}

func withinAny(p string, dirs []string) (string, bool) {
	best := ""
	for _, d := range dirs {
		if within(p, d) && len(d) > len(best) {
			best = d
		}
	}
	return best, best != ""
}

// realOrSelf resolves symlinks when possible so that /tmp -> /private/tmp
// and symlinked homes compare correctly.
func realOrSelf(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}
