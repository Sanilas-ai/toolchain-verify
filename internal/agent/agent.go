package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Options carry environment facts; zero values are filled from the process.
type Options struct {
	Home        string
	Cwd         string
	InContainer bool
	// RequireContainer is the manifest's top-level require_container.
	RequireContainer *bool
	// ManifestDir resolves relative policy paths.
	ManifestDir string
	// ExtraAdvisories are advisory files given on the command line.
	ExtraAdvisories []string
	// ExtraTrusted are trusted roots given on the command line.
	ExtraTrusted []string
	// NoBuiltinAdvisories disables the embedded database.
	NoBuiltinAdvisories bool
	// Strict makes warnings fail.
	Strict bool
	// Getenv defaults to os.Getenv.
	Getenv func(string) string
	// UID defaults to os.Getuid(); -1 disables ownership checks.
	UID *int
	// MaxEntries caps every directory walk (default 200000).
	MaxEntries int
	// AllowUntrustedCwd downgrades cwd.untrusted to a warning and lets
	// RunPreSession pass (--allow-untrusted-cwd).
	AllowUntrustedCwd bool
	// Quarantine moves files behind instr.untrusted / mcp.untrusted-location
	// findings into QuarantineDir (default: policy quarantine_dir, then
	// DefaultQuarantineDir). Off by default: the audit is read-only.
	Quarantine    bool
	QuarantineDir string
	// Now defaults to time.Now (quarantine batch names).
	Now func() time.Time
	// NoHostInventory disables snap / systemd / Docker inventory.
	NoHostInventory bool
	// DockerSocket overrides agent.docker_socket ("off" disables).
	DockerSocket string
	// SnapRoot (default "/snap") and SystemdDirs (default
	// DefaultSystemdDirs) exist for tests.
	SnapRoot    string
	SystemdDirs []string
}

// ErrRefused is returned when the policy asks to scan a credential location.
var ErrRefused = errors.New("refused")

// ErrUntrustedCwd is returned (together with the report) by RunPreSession
// when the working directory is an untrusted location such as Downloads or
// /tmp. It wraps ErrRefused.
var ErrUntrustedCwd = fmt.Errorf("%w: working directory is an untrusted location", ErrRefused)

// resolved is the effective configuration.
type resolved struct {
	home, cwd       string
	trusted         []string
	untrusted       []string
	forbidCwd       []string
	instrPatterns   []string
	untrustedSev    string
	scanDepth       int
	inventory       []string
	inventoryDepth  int
	mcpExtra        []string
	credDirs        []string
	credFiles       []string
	requireExecCont bool
	supplyChain     bool
	getenv          func(string) string
	uid             int
	maxEntries      int
	inContainer     bool
	requireCont     *bool
	allowCwd        bool
	banUnfixed      bool
	hostInventory   bool
	dockerSocket    string
	snapRoot        string
	systemdDirs     []string
	quarantineDir   string // "" = quarantine off
	now             func() time.Time
}

// Resolve applies defaults and safety refusals without touching the disk
// beyond reading ~/.config/user-dirs.dirs.
func resolve(p *Policy, opt Options) (*resolved, error) {
	if p == nil {
		p = &Policy{}
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	r := &resolved{home: opt.Home, cwd: opt.Cwd, getenv: opt.Getenv, inContainer: opt.InContainer, requireCont: opt.RequireContainer}
	if r.home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("home directory: %w", err)
		}
		r.home = h
	}
	r.home = filepath.Clean(r.home)
	if r.cwd == "" {
		c, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		r.cwd = c
	}
	if r.getenv == nil {
		r.getenv = os.Getenv
	}
	r.uid = os.Getuid()
	if opt.UID != nil {
		r.uid = *opt.UID
	}
	r.maxEntries = opt.MaxEntries
	if r.maxEntries <= 0 {
		r.maxEntries = 200000
	}
	base := opt.ManifestDir
	h := r.home
	r.trusted = expandAll(append(append([]string{}, p.TrustedRoots...), opt.ExtraTrusted...), h, base)
	if len(p.UntrustedDirs) > 0 {
		r.untrusted = expandAll(p.UntrustedDirs, h, base)
	} else {
		r.untrusted = DefaultUntrustedDirs(h)
	}
	r.untrusted = dedupe(append(r.untrusted, expandAll(p.ExtraUntrustedDirs, h, base)...))
	if len(p.ForbidCwd) > 0 {
		r.forbidCwd = expandAll(p.ForbidCwd, h, base)
	} else {
		r.forbidCwd = r.untrusted
	}
	if len(p.InstructionFiles) > 0 {
		r.instrPatterns = append([]string{}, p.InstructionFiles...)
	} else {
		r.instrPatterns = append([]string{}, DefaultInstructionFiles...)
	}
	r.instrPatterns = append(r.instrPatterns, p.ExtraInstructionFiles...)
	r.untrustedSev = SevFail
	if p.UntrustedInstruction == "warn" {
		r.untrustedSev = SevWarn
	}
	r.scanDepth = p.ScanDepth
	if r.scanDepth == 0 {
		r.scanDepth = 4
	}
	if len(p.InventoryPaths) > 0 {
		r.inventory = expandAll(p.InventoryPaths, h, base)
	} else {
		r.inventory = dedupe(append(append([]string{}, r.trusted...), DefaultInventoryPaths(h)...))
	}
	r.inventory = dedupe(append(r.inventory, expandAll(p.ExtraInventoryPaths, h, base)...))
	r.inventoryDepth = p.InventoryDepth
	if r.inventoryDepth == 0 {
		r.inventoryDepth = 6
	}
	r.mcpExtra = expandAll(p.MCPConfigs, h, base)
	r.credDirs = dedupe(append(CredentialDirs(h), expandAll(p.CredentialPaths, h, base)...))
	r.credFiles = dedupe(append(CredentialFiles(h), expandAll(p.CredentialPaths, h, base)...))
	r.requireExecCont = boolOr(p.RequireContainerForExec, true)
	r.supplyChain = boolOr(p.SupplyChain, true)
	r.allowCwd = opt.AllowUntrustedCwd
	r.banUnfixed = boolOr(p.BanUnfixed, false)
	r.hostInventory = boolOr(p.HostInventory, true) && !opt.NoHostInventory
	r.dockerSocket = opt.DockerSocket
	if r.dockerSocket == "" && p.DockerSocket != "" {
		r.dockerSocket = p.DockerSocket
		if p.DockerSocket != "off" {
			r.dockerSocket = expand(p.DockerSocket, h, base)
		}
	}
	r.snapRoot = opt.SnapRoot
	if r.snapRoot == "" {
		r.snapRoot = "/snap"
	}
	r.systemdDirs = opt.SystemdDirs
	if r.systemdDirs == nil {
		r.systemdDirs = DefaultSystemdDirs(h)
	}
	r.now = opt.Now
	if r.now == nil {
		r.now = time.Now
	}
	if len(p.InventoryPaths) == 0 {
		// npm -g / pipx with a custom prefix (the prefix in ~/.npmrc is not
		// read: .npmrc is a credential file).
		if v := r.getenv("NPM_CONFIG_PREFIX"); filepath.IsAbs(v) {
			r.inventory = dedupe(append(r.inventory, filepath.Join(filepath.Clean(v), "lib")))
		}
		if v := r.getenv("PIPX_HOME"); filepath.IsAbs(v) {
			r.inventory = dedupe(append(r.inventory, filepath.Join(filepath.Clean(v), "venvs")))
		}
	}

	// Refuse to walk credential locations. A planted instruction file may try
	// to talk an agent into "verifying" ~/.codex or ~/.config/gh with this
	// tool so that the output (or a later step) leaks tokens.
	walkTargets := map[string][]string{
		"trusted_roots": r.trusted, "untrusted_dirs": r.untrusted, "inventory_paths": r.inventory,
	}
	for key, list := range walkTargets {
		for _, d := range list {
			if c, bad := r.credentialHit(d); bad {
				return nil, fmt.Errorf("%w: agent.%s entry %s is (or is inside) credential location %s; this tool never scans credential stores", ErrRefused, key, d, c)
			}
			if d == "/" || d == r.home {
				if key != "trusted_roots" {
					return nil, fmt.Errorf("%w: agent.%s entry %s is too broad (it contains credential stores); list specific directories", ErrRefused, key, d)
				}
			}
		}
	}
	for _, f := range r.mcpExtra {
		if c, bad := r.credentialFileHit(f); bad {
			return nil, fmt.Errorf("%w: agent.mcp_configs entry %s is a credential file (%s); it will not be opened", ErrRefused, f, c)
		}
	}
	for _, t := range r.trusted {
		if t == "/" || t == r.home {
			return nil, fmt.Errorf("%w: agent.trusted_roots entry %s would trust every instruction file below it (including Downloads); list project directories instead", ErrRefused, t)
		}
	}
	if opt.Quarantine {
		q := opt.QuarantineDir
		if q != "" {
			q = expand(q, h, "")
			if !filepath.IsAbs(q) {
				if a, err := filepath.Abs(q); err == nil {
					q = a
				}
			}
		} else if p.QuarantineDir != "" {
			q = expand(p.QuarantineDir, h, base)
		} else {
			q = DefaultQuarantineDir(h)
		}
		if err := r.checkQuarantineDir(q); err != nil {
			return nil, err
		}
		r.quarantineDir = q
	}
	return r, nil
}

func (r *resolved) credentialHit(p string) (string, bool) {
	if c, ok := withinAny(p, r.credDirs); ok {
		return c, true
	}
	return r.credentialFileHit(p)
}

func (r *resolved) credentialFileHit(p string) (string, bool) {
	for _, cf := range r.credFiles {
		if strings.ContainsAny(filepath.Base(cf), "*?[") {
			if ok, _ := filepath.Match(cf, p); ok {
				return cf, true
			}
			continue
		}
		if filepath.Clean(p) == cf {
			return cf, true
		}
	}
	return "", false
}

func (r *resolved) isTrusted(p string) bool {
	_, ok := withinAny(p, r.trusted)
	if !ok {
		_, ok = withinAny(realOrSelf(p), r.trusted)
	}
	return ok
}

func (r *resolved) isUntrustedDir(p string) (string, bool) {
	if r.isTrusted(p) {
		return "", false
	}
	if d, ok := withinAny(p, r.forbidCwd); ok {
		return d, true
	}
	if d, ok := withinAny(realOrSelf(p), r.forbidCwd); ok {
		return d, true
	}
	return "", false
}

// UntrustedCwd reports whether cwd lies in a default untrusted directory
// (Downloads, Desktop, /tmp, ...) and is not under one of trusted. It is
// used by `check` to refuse auto-loading a manifest planted there.
func UntrustedCwd(cwd, home string, trusted []string) (string, bool) {
	r := &resolved{home: home, trusted: expandAll(trusted, home, ""), forbidCwd: DefaultUntrustedDirs(home)}
	return r.isUntrustedDir(cwd)
}

// Run executes all agent-protection checks.
func Run(p *Policy, opt Options) (*Report, error) {
	r, err := resolve(p, opt)
	if err != nil {
		return nil, err
	}
	var extra []string
	if p != nil {
		extra = expandAll(p.Advisories, r.home, opt.ManifestDir)
	}
	extra = append(extra, opt.ExtraAdvisories...)
	builtin := !opt.NoBuiltinAdvisories && (p == nil || boolOr(p.BuiltinAdvisories, true))
	db, err := LoadDB(builtin, extra)
	if err != nil {
		return nil, err
	}
	c := &collector{}
	if p != nil {
		c.ignore = p.Ignore
	}
	strict := opt.Strict || (p != nil && p.Strict)
	rep := &Report{InContainer: r.inContainer, Home: r.home, Cwd: r.cwd, Strict: strict, AdvisoryDB: db.Updated, TrustedRoots: r.trusted}

	checkCwd(r, c)
	mcpFiles := checkInstructions(r, c, rep)
	var hostInstalls []Install
	if r.hostInventory {
		var roots []string
		roots, hostInstalls = hostInventory(r, db, c, rep)
		for _, root := range roots {
			if _, bad := r.credentialHit(root); bad || root == "/" || root == r.home {
				continue
			}
			r.inventory = dedupe(append(r.inventory, root))
		}
	}
	installs := append(inventory(r, db, c, rep), hostInstalls...)
	rep.Installs = installs
	execSurface := checkStacks(r, db, c, installs)
	execSurface += checkMCP(r, c, mcpFiles)
	checkCredentials(r, c)
	if r.supplyChain {
		checkSupplyChain(r, c)
	}
	if execSurface > 0 && (r.requireCont == nil || !*r.requireCont) {
		c.add(Finding{Rule: "policy.require-container", Severity: SevWarn,
			Message: fmt.Sprintf("%d exec-capable agent tool surface(s) found (agent stacks, stdio MCP servers, approval bypass) but the manifest does not set require_container = true", execSurface),
			Fix:     "set require_container = true in the manifest and run agents/tools inside a disposable, non-root container with an empty env and egress allow-list"})
	}

	r.finish(c, rep, strict)
	return rep, nil
}

// finish applies quarantine and computes the verdict.
func (r *resolved) finish(c *collector, rep *Report, strict bool) {
	if r.quarantineDir != "" {
		r.quarantine(c, rep)
	}
	rep.Findings = c.sorted()
	rep.Ignored = c.ignored
	fail, warn, _ := rep.Counts()
	rep.OK = fail == 0 && (!strict || warn == 0)
}

// RunPreSession is the fast gate to run right before starting a coding
// agent (`toolchain-verify agent --pre-session && codex`). It evaluates only
// the working directory: cwd.untrusted, cwd.instructions,
// cwd.ancestor-instructions and, when cwd is inside an untrusted location,
// the instruction/MCP files below it (which --quarantine can move away).
// Advisories, MCP settings and credentials are not checked.
//
// When the report keeps a failing cwd.untrusted finding (not downgraded by
// AllowUntrustedCwd or suppressed by agent.ignore) the report is returned
// together with ErrUntrustedCwd.
func RunPreSession(p *Policy, opt Options) (*Report, error) {
	r, err := resolve(p, opt)
	if err != nil {
		return nil, err
	}
	c := &collector{}
	if p != nil {
		c.ignore = p.Ignore
	}
	strict := opt.Strict || (p != nil && p.Strict)
	rep := &Report{InContainer: r.inContainer, Home: r.home, Cwd: r.cwd, Strict: strict, TrustedRoots: r.trusted, PreSession: true}
	checkCwd(r, c)
	cwd := filepath.Clean(r.cwd)
	if d, ut := r.isUntrustedDir(cwd); ut {
		var configs []foundConfig
		r.scanUntrustedDir(c, rep, d, cwd, &walkStats{}, &configs)
		for _, fc := range configs {
			c.add(Finding{Rule: "mcp.untrusted-location", Severity: r.untrustedSev, Path: fc.path,
				Message: fmt.Sprintf("MCP/agent config in untrusted location %s; an agent started there would load its servers and permissions", fc.untrusted),
				Fix:     "delete it unless you created it; never start agents in this directory"})
		}
	}
	r.finish(c, rep, strict)
	for _, f := range rep.Findings {
		if f.Rule == "cwd.untrusted" && f.Severity == SevFail {
			return rep, ErrUntrustedCwd
		}
	}
	return rep, nil
}

func checkCwd(r *resolved, c *collector) {
	cwd := filepath.Clean(r.cwd)
	untrustedCwd := false
	if d, bad := r.isUntrustedDir(cwd); bad {
		untrustedCwd = true
		sev := SevFail
		msg := fmt.Sprintf("working directory is inside untrusted location %s; coding agents started here load AGENTS.md/CLAUDE.md and MCP configs planted by browsers or archives", d)
		if r.allowCwd {
			sev = SevWarn
			msg += " (allowed by --allow-untrusted-cwd)"
		}
		c.add(Finding{Rule: "cwd.untrusted", Severity: sev, Path: cwd,
			Message: msg,
			Fix:     "cd into a trusted project (agent.trusted_roots) before starting an agent; never use Downloads or /tmp as a project root",
			Refs:    []string{"https://www.bleepingcomputer.com/news/security/ai-coding-agents-hijacked-using-agentsmd-file-in-downloads-folder/"}})
	}
	// Instruction files in the working directory itself (and nested rule
	// dirs such as .github/ or .cursor/rules) when cwd is neither trusted
	// nor an untrusted location (those are reported by instr.untrusted):
	// e.g. a freshly cloned or unpacked project outside the trusted roots.
	if !untrustedCwd && cwd != r.home && !r.isTrusted(cwd) {
		if _, bad := r.credentialHit(cwd); !bad {
			sev := SevWarn
			if len(r.trusted) > 0 {
				sev = SevFail
			}
			for _, f := range r.cwdInstructionFiles(cwd) {
				msg := "agent instruction file in the working directory, which is outside the trusted roots; an agent started here follows it"
				if hits := r.scanContent(f, false); len(hits) > 0 {
					msg += " (content flags: " + strings.Join(hits, ", ") + ")"
				}
				c.add(Finding{Rule: "cwd.instructions", Severity: sev, Path: f, Message: msg,
					Fix: "review it before starting an agent here; if you trust this project add it to agent.trusted_roots (or --trusted)"})
			}
		}
	}
	if cwd == r.home {
		c.add(Finding{Rule: "cwd.home", Severity: SevWarn, Path: cwd,
			Message: "working directory is the home directory; an agent started here can read every dotfile, including credential stores",
			Fix:     "start agents inside a specific project directory"})
	}
	// Instruction files in ancestors are loaded by several agents (Claude
	// Code walks up to /, Codex from the git root). Flag ancestors that are
	// not inside a trusted root.
	for dir := filepath.Dir(cwd); ; dir = filepath.Dir(dir) {
		if !r.isTrusted(dir) {
			if _, bad := r.credentialHit(dir); !bad {
				for _, f := range instructionFilesIn(dir, r.instrPatterns) {
					sev := SevWarn
					if _, ut := r.isUntrustedDir(dir); ut || len(r.trusted) > 0 {
						sev = SevFail
					}
					c.add(Finding{Rule: "cwd.ancestor-instructions", Severity: sev, Path: f,
						Message: "instruction file in a parent of the working directory, outside trusted roots; agents may merge it into their instructions",
						Fix:     "remove or move it, or add the directory to agent.trusted_roots if you wrote it"})
				}
			}
		}
		if dir == filepath.Dir(dir) {
			break
		}
	}
}

// cwdInstructionFiles lists instruction files in cwd up to three levels
// deep (AGENTS.md, .github/copilot-instructions.md, .cursor/rules/x.mdc,
// nested AGENTS.md), skipping dependency directories.
func (r *resolved) cwdInstructionFiles(cwd string) []string {
	var out []string
	r.walk(cwd, 3, nil, &walkStats{}, func(p string, d fs.DirEntry) error {
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", ".venv", "venv", "site-packages", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if matchInstruction(p, r.instrPatterns) {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// instructionFilesIn lists instruction files directly in dir (base-name
// patterns only; nested patterns like .github/... are handled by walks).
func instructionFilesIn(dir string, patterns []string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		if matchInstruction(filepath.Join(dir, e.Name()), patterns) {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}
