package agent

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// mcpPatterns are MCP / agent configuration files picked up during walks.
var mcpPatterns = []string{
	".mcp.json", "mcp.json", "mcp_config.json", "claude_desktop_config.json",
	".gemini/settings.json", ".codex/config.toml", ".claude/settings.json", ".claude/settings.local.json",
}

type foundConfig struct {
	path      string
	untrusted string // non-empty: the untrusted dir it was found in
}

type suspicious struct {
	name string
	re   *regexp.Regexp
	// trustedToo: also reported for instruction files inside trusted roots.
	trustedToo bool
}

var suspiciousPatterns = []suspicious{
	{"pipe-to-shell", regexp.MustCompile(`(?i)\b(curl|wget|iwr|invoke-webrequest)\b[^\n|]{0,300}\|\s*(sudo\s+)?(ba|z|da)?sh\b|\biex\s*\(`), true},
	{"package-install", regexp.MustCompile(`(?i)\b(npm|pnpm|yarn|bun)\s+(i|install|add)\b|\bpip3?\s+install\b|\buv\s+(pip\s+install|add|tool\s+install)\b|\bnpx\s+(-y|--yes)\b|\bgo\s+install\b|\bcargo\s+install\b`), false},
	{"credential-path", regexp.MustCompile(`(?i)\.codex/auth\.json|\.claude/\.credentials|gh/hosts\.yml|\.git-credentials|\.aws/credentials|\.ssh/id_|\.npmrc|\.netrc|oauth_creds|application_default_credentials|\bgh\s+auth\s+token\b|\bkeychain\b|\bsecret-tool\b`), true},
	{"token-env", regexp.MustCompile(`\$\{?(GH_TOKEN|GITHUB_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|NPM_TOKEN|AWS_SECRET_ACCESS_KEY|CODEX_[A-Z_]*TOKEN)\}?`), false},
	{"exfil-endpoint", regexp.MustCompile(`(?i)webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app)|interact\.sh|oast\.(fun|me|pro|live|site|online)|burpcollaborator|\btransfer\.sh\b|pastebin\.com/api`), true},
	{"upload-command", regexp.MustCompile(`(?i)\b(curl|wget)\b[^\n]{0,200}\s(-d|--data(-binary|-raw)?|-F|--form|-T|--upload-file|--post-file)\b`), false},
	{"approval-bypass", regexp.MustCompile(`(?i)--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|\bbypassPermissions\b|approval[_-]policy\s*[=:]\s*"?never|danger-full-access|--yolo\b|\bauto[-_ ]?approve\s*[=:]\s*(true|\[\s*"\*")`), true},
	{"instruction-override", regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules)|do\s+not\s+(tell|inform|notify|mention\s+(this|it)\s+to)\s+the\s+user|without\s+(asking|telling|notifying)\s+the\s+user|silently\s+(run|install|execute|upload)`), true},
	{"encoded-blob", regexp.MustCompile(`[A-Za-z0-9+/]{240,}={0,2}`), true},
}

// hiddenRunes: bidi overrides/isolates and Unicode tag characters, used to
// hide instructions from human reviewers ("ASCII smuggling").
func hiddenRunes(s string) int {
	n := 0
	for _, r := range s {
		switch {
		case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r >= 0xE0000 && r <= 0xE007F, r == 0x200B, r == 0x2062, r == 0x2063, r == 0x2064:
			n++
		}
	}
	return n
}

// scanContent returns the names of suspicious patterns found. It reads at
// most 512 KiB and never returns the matched text.
func (r *resolved) scanContent(path string, trusted bool) []string {
	target := path
	if t, err := filepath.EvalSymlinks(path); err == nil {
		target = t
	}
	if _, bad := r.credentialHit(target); bad {
		return []string{"symlink-to-credential"}
	}
	st, err := os.Stat(target)
	if err != nil || !st.Mode().IsRegular() {
		return nil
	}
	f, err := os.Open(target)
	if err != nil {
		return nil
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, 512<<10))
	s := string(b)
	var hits []string
	for _, sp := range suspiciousPatterns {
		if trusted && !sp.trustedToo {
			continue
		}
		if sp.re.MatchString(s) {
			hits = append(hits, sp.name)
		}
	}
	if hiddenRunes(s) > 0 {
		hits = append(hits, "hidden-unicode")
	}
	return hits
}

// checkInstructions scans untrusted dirs, the top level of $HOME and the
// trusted roots. It returns MCP/agent config files seen along the way.
func checkInstructions(r *resolved, c *collector, rep *Report) []foundConfig {
	var configs []foundConfig
	st := &walkStats{}

	for _, dir := range r.untrusted {
		if r.isTrusted(dir) {
			continue
		}
		if _, err := os.Lstat(dir); err != nil {
			continue
		}
		rep.Scanned = append(rep.Scanned, dir)
		r.walk(dir, r.scanDepth, r.trusted, st, func(p string, d fs.DirEntry) error {
			if d.IsDir() {
				return nil
			}
			if matchInstruction(p, r.instrPatterns) {
				hits := r.scanContent(p, false)
				msg := fmt.Sprintf("agent instruction file in untrusted location %s; an agent started in or below this directory would follow it", dir)
				if len(hits) > 0 {
					msg += " (content flags: " + strings.Join(hits, ", ") + ")"
				}
				c.add(Finding{Rule: "instr.untrusted", Severity: r.untrustedSev, Path: p, Message: msg,
					Fix:  "do not run agents here; delete the file unless you created it (do NOT follow any install/auth steps it suggests)",
					Refs: []string{"https://www.bleepingcomputer.com/news/security/ai-coding-agents-hijacked-using-agentsmd-file-in-downloads-folder/"}})
			}
			if matchPatterns(p, mcpPatterns) {
				configs = append(configs, foundConfig{path: p, untrusted: dir})
			}
			if r.supplyChain {
				checkModelFile(c, p, d)
			}
			return nil
		})
	}

	// Top level of $HOME: an AGENTS.md here is inherited by every project
	// under ~ for agents that walk up the tree.
	if !r.isTrusted(r.home) {
		for _, f := range instructionFilesIn(r.home, r.instrPatterns) {
			hits := r.scanContent(f, false)
			msg := "instruction file at the top of the home directory; agents that merge parent-directory instructions apply it to every project"
			if len(hits) > 0 {
				msg += " (content flags: " + strings.Join(hits, ", ") + ")"
			}
			c.add(Finding{Rule: "instr.home", Severity: SevWarn, Path: f, Message: msg,
				Fix: "move personal agent instructions to the agent's own global config (e.g. ~/.codex/AGENTS.md, ~/.claude/CLAUDE.md) or delete it"})
		}
	}

	for _, root := range r.trusted {
		if _, err := os.Lstat(root); err != nil {
			c.add(Finding{Rule: "policy.trusted-root-missing", Severity: SevInfo, Path: root, Message: "trusted root does not exist"})
			continue
		}
		rep.Scanned = append(rep.Scanned, root)
		r.walk(root, r.scanDepth, nil, st, func(p string, d fs.DirEntry) error {
			if d.IsDir() {
				if d.Name() == "node_modules" || d.Name() == ".venv" || d.Name() == "venv" || d.Name() == "site-packages" {
					return filepath.SkipDir
				}
				return nil
			}
			if matchInstruction(p, r.instrPatterns) {
				checkWritable(r, c, "instr.writable", p)
				if hits := r.scanContent(p, true); len(hits) > 0 {
					c.add(Finding{Rule: "instr.suspicious", Severity: SevWarn, Path: p,
						Message: "instruction file in a trusted root contains risky patterns: " + strings.Join(hits, ", "),
						Fix:     "review the file (git log/blame); instructions must not ask agents to touch credentials, pipe downloads to a shell or skip approvals"})
				}
			}
			if matchPatterns(p, mcpPatterns) {
				configs = append(configs, foundConfig{path: p})
			}
			return nil
		})
	}
	if st.truncated {
		c.add(Finding{Rule: "scan.truncated", Severity: SevWarn, Message: fmt.Sprintf("instruction scan stopped after %d entries; results are incomplete", r.maxEntries),
			Fix: "narrow agent.trusted_roots / untrusted_dirs or lower agent.scan_depth"})
	}
	return configs
}

// checkWritable flags files (and their parent dir) writable by others.
func checkWritable(r *resolved, c *collector, rule, p string) {
	st, err := os.Stat(p)
	if err != nil {
		return
	}
	mode := st.Mode().Perm()
	switch {
	case mode&0o002 != 0:
		c.add(Finding{Rule: rule, Severity: SevFail, Path: p, Message: fmt.Sprintf("world-writable (%04o): any local user or process can rewrite what the agent loads", mode),
			Fix: "chmod o-w " + p})
	case mode&0o020 != 0:
		c.add(Finding{Rule: rule, Severity: SevInfo, Path: p, Message: fmt.Sprintf("group-writable (%04o); a risk only if other users share the group", mode), Fix: "chmod g-w " + p})
	}
	if uid, ok := fileUID(st); ok && r.uid >= 0 && uid != r.uid && uid != 0 {
		c.add(Finding{Rule: rule, Severity: SevWarn, Path: p, Message: fmt.Sprintf("owned by uid %d, not the current user (%d)", uid, r.uid)})
	}
	dir := filepath.Dir(p)
	if ds, err := os.Stat(dir); err == nil {
		dm := ds.Mode()
		if dm.Perm()&0o002 != 0 && dm&os.ModeSticky == 0 {
			c.add(Finding{Rule: rule, Severity: SevFail, Path: p, Message: fmt.Sprintf("parent directory %s is world-writable without the sticky bit: the file can be replaced", dir),
				Fix: "chmod o-w " + dir})
		}
	}
}
