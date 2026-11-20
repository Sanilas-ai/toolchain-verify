package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// checkHooks requires that an installed Claude or Cursor client actually
// calls this binary. A missing client directory is not a finding: there is
// no agent to bind. A settings file that exists without the hook is
// agent.hook-missing. A hook whose command is some other program is
// agent.hook-substituted. Secret files are not opened.
func checkHooks(r *resolved, c *collector) {
	checkClaudeHook(c, filepath.Join(r.home, ".claude", "settings.json"))
	if r.cwd != "" {
		checkClaudeHook(c, filepath.Join(r.cwd, ".claude", "settings.json"))
	}
	checkCursorHook(c, filepath.Join(r.home, ".cursor", "hooks.json"))
}

func checkClaudeHook(c *collector, path string) {
	cmds, ok := hookCommands(path, "PreToolUse", true)
	if !ok {
		return
	}
	judgeHook(c, path, cmds, "--hook claude", "PreToolUse Bash")
}

func checkCursorHook(c *collector, path string) {
	cmds, ok := hookCommands(path, "beforeShellExecution", false)
	if !ok {
		return
	}
	judgeHook(c, path, cmds, "--hook cursor", "beforeShellExecution")
}

func judgeHook(c *collector, path string, cmds []string, flag, what string) {
	if len(cmds) == 0 {
		c.add(Finding{Rule: "agent.hook-missing", Severity: SevFail, Path: path,
			Message: what + " hook is not set; shell commands from the agent are not checked",
			Fix:     "point the hook at `toolchain-verify policy check " + flag + "`"})
		return
	}
	for _, cmd := range cmds {
		if hookMatches(cmd, flag) {
			return
		}
	}
	c.add(Finding{Rule: "agent.hook-substituted", Severity: SevFail, Path: path,
		Message: what + " hook does not invoke toolchain-verify " + flag,
		Fix:     "set the hook command to `toolchain-verify policy check " + flag + "`"})
}

func hookMatches(cmd, flag string) bool {
	low := strings.ToLower(cmd)
	if !strings.Contains(low, "toolchain-verify") {
		return false
	}
	return strings.Contains(low, strings.ToLower(flag))
}

// hookCommands reads a client settings file (never a credential file) and
// returns the hook commands for event. ok is false when the file is absent.
// claude filters PreToolUse entries to matcher Bash (or an empty matcher).
func hookCommands(path, event string, claude bool) ([]string, bool) {
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case "auth.json", "credentials.json", ".credentials.json", "hosts.yml":
		return nil, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	if len(b) > 1<<20 {
		b = b[:1<<20]
	}
	var doc struct {
		Hooks map[string]json.RawMessage `json:"hooks"`
	}
	if json.Unmarshal(b, &doc) != nil || doc.Hooks == nil {
		return nil, true
	}
	raw, ok := doc.Hooks[event]
	if !ok {
		return nil, true
	}
	if claude {
		return claudeCommands(raw), true
	}
	return cursorCommands(raw), true
}

func claudeCommands(raw json.RawMessage) []string {
	var entries []struct {
		Matcher string `json:"matcher"`
		Hooks   []struct {
			Type    string `json:"type"`
			Command string `json:"command"`
		} `json:"hooks"`
	}
	if json.Unmarshal(raw, &entries) != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		m := strings.ToLower(strings.TrimSpace(e.Matcher))
		if m != "" && m != "bash" && m != "*" {
			continue
		}
		for _, h := range e.Hooks {
			if h.Command != "" && (h.Type == "" || strings.EqualFold(h.Type, "command")) {
				out = append(out, h.Command)
			}
		}
	}
	return out
}

func cursorCommands(raw json.RawMessage) []string {
	var entries []struct {
		Command string `json:"command"`
	}
	if json.Unmarshal(raw, &entries) != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.Command != "" {
			out = append(out, e.Command)
		}
	}
	return out
}
