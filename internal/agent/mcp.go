package agent

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// DefaultMCPConfigs are user-level MCP / agent config files (relative to $HOME).
var DefaultMCPConfigs = []string{
	".cursor/mcp.json",
	".codeium/windsurf/mcp_config.json",
	".config/Claude/claude_desktop_config.json",
	".claude.json",
	".claude/settings.json",
	".gemini/settings.json",
	".codex/config.toml",
	".config/Code/User/mcp.json",
	".config/Code/User/settings.json",
	".config/Cursor/User/settings.json",
	".config/zed/settings.json",
	".srt-settings.json",
}

// projectMCPConfigs are looked up in the working directory.
var projectMCPConfigs = []string{
	".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".vscode/settings.json",
	".gemini/settings.json", ".codex/config.toml", ".claude/settings.json", ".claude/settings.local.json",
	".srt-settings.json",
}

type mcpServer struct {
	name        string
	command     string
	args        []string
	url         string
	env         map[string]string
	headers     map[string]string
	autoApprove []string
	trust       bool
	disabled    bool
}

func checkMCP(r *resolved, c *collector, found []foundConfig) []ExecSurface {
	byPath := map[string]foundConfig{}
	for _, rel := range DefaultMCPConfigs {
		p := filepath.Join(r.home, filepath.FromSlash(rel))
		byPath[p] = foundConfig{path: p}
	}
	for _, rel := range projectMCPConfigs {
		p := filepath.Join(r.cwd, filepath.FromSlash(rel))
		fc := foundConfig{path: p}
		if d, bad := r.isUntrustedDir(r.cwd); bad {
			fc.untrusted = d
		}
		byPath[p] = fc
	}
	for _, p := range r.mcpExtra {
		byPath[p] = foundConfig{path: p}
	}
	for _, f := range found {
		byPath[f.path] = f
	}
	paths := make([]string, 0, len(byPath))
	for p := range byPath {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var surfaces []ExecSurface
	for _, p := range paths {
		fc := byPath[p]
		if _, bad := r.credentialFileHit(p); bad {
			continue // never open token files, even if named like a config
		}
		st, err := os.Stat(p)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		editorSettings := isEditorSettingsPath(p)
		if !editorSettings {
			checkWritable(r, c, "mcp.writable", p)
		}
		if fc.untrusted != "" {
			c.add(Finding{Rule: "mcp.untrusted-location", Severity: r.untrustedSev, Path: p,
				Message: fmt.Sprintf("MCP/agent config in untrusted location %s; an agent started there would load its servers and permissions", fc.untrusted),
				Fix:     "delete it unless you created it; never start agents in this directory"})
		}
		b, err := readLimited(p, 16<<20)
		if err != nil {
			continue
		}
		var doc map[string]any
		if strings.HasSuffix(p, ".toml") {
			if _, err := toml.Decode(string(b), &doc); err != nil {
				c.add(Finding{Rule: "mcp.parse", Severity: SevWarn, Path: p, Message: "cannot parse TOML: " + err.Error()})
				continue
			}
		} else if err := json.Unmarshal(stripJSONC(b), &doc); err != nil {
			c.add(Finding{Rule: "mcp.parse", Severity: SevWarn, Path: p, Message: "cannot parse JSON: " + err.Error()})
			continue
		}
		// Editor settings.json often holds only eslint/format options. Flag
		// mcp.writable only when the file actually configures MCP.
		if editorSettings && hasMCPKeys(doc) {
			checkWritable(r, c, "mcp.writable", p)
		}
		surfaces = append(surfaces, auditAgentSettings(r, c, p, doc)...)
		for _, s := range extractServers(doc) {
			surfaces = append(surfaces, auditServer(r, c, p, s)...)
		}
	}
	return surfaces
}

// isEditorSettingsPath reports VS Code / Cursor / Zed settings.json files
// (user-level or project .vscode/settings.json). These frequently contain
// only editor preferences and must not be labelled mcp.writable unless they
// actually configure MCP.
func isEditorSettingsPath(p string) bool {
	slash := filepath.ToSlash(p)
	if strings.HasSuffix(slash, "/.vscode/settings.json") {
		return true
	}
	for _, suf := range []string{
		"/.config/Code/User/settings.json",
		"/.config/Cursor/User/settings.json",
		"/.config/zed/settings.json",
	} {
		if strings.HasSuffix(slash, suf) {
			return true
		}
	}
	return false
}

// hasMCPKeys reports whether a parsed settings/config document configures
// MCP servers or VS Code/Cursor chat.mcp.* / mcp.* keys.
func hasMCPKeys(doc map[string]any) bool {
	if doc == nil {
		return false
	}
	for _, k := range []string{"mcpServers", "servers", "mcp_servers", "context_servers", "mcp"} {
		if _, ok := doc[k]; ok {
			return true
		}
	}
	for k := range doc {
		if strings.HasPrefix(k, "mcp.") || strings.HasPrefix(k, "chat.mcp.") {
			return true
		}
	}
	return false
}

// extractServers finds MCP server maps under the keys used by Cursor,
// Claude (desktop/code), VS Code, Windsurf, Gemini CLI, Codex and Zed.
func extractServers(doc map[string]any) []mcpServer {
	var out []mcpServer
	var visit func(m map[string]any, depth int)
	visit = func(m map[string]any, depth int) {
		for k, v := range m {
			sub, ok := v.(map[string]any)
			if !ok {
				continue
			}
			switch k {
			case "mcpServers", "servers", "mcp_servers", "context_servers":
				names := make([]string, 0, len(sub))
				for n := range sub {
					names = append(names, n)
				}
				sort.Strings(names)
				for _, n := range names {
					if sm, ok := sub[n].(map[string]any); ok {
						out = append(out, toServer(n, sm))
					}
				}
			case "mcp", "projects":
				if depth < 3 {
					visit(sub, depth+1)
				}
			default:
				if depth > 0 && depth < 3 { // projects.<path>.mcpServers
					visit(sub, depth+1)
				}
			}
		}
	}
	visit(doc, 0)
	return out
}

func toServer(name string, m map[string]any) mcpServer {
	s := mcpServer{name: name, env: map[string]string{}, headers: map[string]string{}}
	str := func(k string) string { v, _ := m[k].(string); return v }
	s.command = str("command")
	if cm, ok := m["command"].(map[string]any); ok { // zed: {"command": {"path":..., "args":[...]}}
		s.command, _ = cm["path"].(string)
		s.args = strList(cm["args"])
	}
	if len(s.args) == 0 {
		s.args = strList(m["args"])
	}
	for _, k := range []string{"url", "serverUrl", "httpUrl", "server_url"} {
		if v := str(k); v != "" {
			s.url = v
			break
		}
	}
	for k, v := range mapStr(m["env"]) {
		s.env[k] = v
	}
	for k, v := range mapStr(m["headers"]) {
		s.headers[k] = v
	}
	s.autoApprove = append(strList(m["autoApprove"]), strList(m["alwaysAllow"])...)
	s.autoApprove = append(s.autoApprove, strList(m["auto_approve"])...)
	if b, ok := m["autoApprove"].(bool); ok && b {
		s.autoApprove = append(s.autoApprove, "*")
	}
	s.trust, _ = m["trust"].(bool)
	s.disabled, _ = m["disabled"].(bool)
	if en, ok := m["enabled"].(bool); ok && !en {
		s.disabled = true
	}
	return s
}

func strList(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		if ss, ok := v.([]string); ok {
			return ss
		}
		return nil
	}
	var out []string
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func mapStr(v any) map[string]string {
	out := map[string]string{}
	if m, ok := v.(map[string]any); ok {
		for k, x := range m {
			if s, ok := x.(string); ok {
				out[k] = s
			}
		}
	}
	return out
}

var secretKeyRe = regexp.MustCompile(`(?i)(token|secret|passw|api[_-]?key|private[_-]?key|authorization|credential|cookie)`)

func isLiteralSecret(v string) bool {
	v = strings.TrimSpace(v)
	if len(v) < 8 {
		return false
	}
	if strings.HasPrefix(v, "${") || strings.HasPrefix(v, "$") || strings.HasPrefix(v, "env:") || strings.HasPrefix(v, "{env:") || strings.Contains(v, "${input:") || strings.Contains(v, "${env:") {
		return false
	}
	if strings.HasPrefix(strings.ToLower(v), "bearer ${") {
		return false
	}
	return true
}

func isLoopback(host string) bool {
	h := strings.Trim(host, "[]")
	if strings.EqualFold(h, "localhost") || strings.HasSuffix(strings.ToLower(h), ".localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

var runners = map[string]bool{"npx": true, "bunx": true, "uvx": true, "pnpx": true}
var shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "fish": true, "cmd": true, "cmd.exe": true, "powershell": true, "pwsh": true, "powershell.exe": true}
var pipeShellRe = regexp.MustCompile(`(?i)\b(curl|wget)\b.*\|\s*(sudo\s+)?(ba|z|da)?sh\b`)

func auditServer(r *resolved, c *collector, path string, s mcpServer) []ExecSurface {
	if s.disabled {
		return nil
	}
	id := fmt.Sprintf("server %q", s.name)
	var surfaces []ExecSurface
	remote := false
	if s.url != "" {
		u, err := url.Parse(s.url)
		switch {
		case err != nil || u.Host == "":
			c.add(Finding{Rule: "mcp.bad-url", Severity: SevWarn, Path: path, Message: id + ": unparseable URL"})
		case isLoopback(u.Hostname()):
		case u.Scheme == "http" || u.Scheme == "ws":
			remote = true
			c.add(Finding{Rule: "mcp.remote-cleartext", Severity: SevFail, Path: path,
				Message: fmt.Sprintf("%s: remote MCP server over cleartext %s://%s; tool descriptions and results can be modified in transit", id, u.Scheme, u.Host),
				Fix:     "use https (or remove the server)"})
		default:
			remote = true
			c.add(Finding{Rule: "mcp.remote", Severity: SevInfo, Path: path,
				Message: fmt.Sprintf("%s: remote MCP server %s; its tool descriptions are untrusted input (tool poisoning / rug-pull)", id, u.Host)})
		}
	}
	all := s.trust
	for _, a := range s.autoApprove {
		if a == "*" || a == "all" {
			all = true
		}
	}
	if len(s.autoApprove) > 0 || s.trust {
		sev := SevWarn
		what := fmt.Sprintf("%d tool(s) auto-approved", len(s.autoApprove))
		if all {
			what = "all tools auto-approved"
			sev = SevFail
		}
		if remote {
			sev = SevFail
			what += " on a remote server"
		}
		c.add(Finding{Rule: "mcp.auto-approve", Severity: sev, Path: path,
			Message: id + ": " + what + "; a prompt injection can call them without a human gate",
			Fix:     "remove autoApprove/alwaysAllow/trust for tools that write, execute, spend or reach the network"})
		surfaces = append(surfaces, ExecSurface{
			Path: path, Kind: "approval-bypass",
			Why: fmt.Sprintf("%s: %s (MCP approval bypass)", id, what),
		})
	}
	if s.command != "" {
		cmd := strings.ToLower(filepath.Base(s.command))
		surfaces = append(surfaces, ExecSurface{
			Path: path, Kind: "stdio-mcp",
			Why: fmt.Sprintf("%s: stdio MCP server runs local command %q (model-controlled tool calls become process exec)", id, s.command),
		})
		args := s.args
		joined := s.command + " " + strings.Join(args, " ")
		if pipeShellRe.MatchString(joined) {
			c.add(Finding{Rule: "mcp.pipe-to-shell", Severity: SevFail, Path: path, Message: id + ": command downloads and pipes code into a shell at every start"})
		} else if shells[cmd] && containsAny(args, "-c", "/c", "-Command", "-command") {
			c.add(Finding{Rule: "mcp.shell", Severity: SevWarn, Path: path, Message: id + ": server is started through a shell -c string; prefer an explicit binary and args"})
		}
		if pkg, pinned := runnerPackage(cmd, args); pkg != "" && !pinned {
			c.add(Finding{Rule: "mcp.unpinned", Severity: SevWarn, Path: path,
				Message: fmt.Sprintf("%s: %s fetches %q without a pinned version at every start; a compromised or typo-squatted release runs with your privileges", id, cmd, pkg),
				Fix:     "pin an exact version (npx pkg@1.2.3 / uvx pkg==1.2.3) or install it once and reference the binary"})
		}
		if cmd == "docker" || cmd == "podman" {
			if containsAny(args, "--privileged") || hasArgPrefix(args, "/var/run/docker.sock", "-v=/:", "/:/") || containsAny(args, "--network=host", "--pid=host") {
				c.add(Finding{Rule: "mcp.container-escape", Severity: SevWarn, Path: path, Message: id + ": container is started privileged / with host namespaces or the docker socket, which defeats the sandbox"})
			}
		}
	}
	for k, v := range s.env {
		if secretKeyRe.MatchString(k) && isLiteralSecret(v) {
			c.add(Finding{Rule: "mcp.inline-secret", Severity: SevWarn, Path: path,
				Message: fmt.Sprintf("%s: env %s holds a literal secret in the config file (value not shown)", id, k),
				Fix:     "reference an environment variable or the OS keychain instead of storing the value in the file"})
		}
	}
	for k, v := range s.headers {
		if secretKeyRe.MatchString(k) && isLiteralSecret(v) {
			c.add(Finding{Rule: "mcp.inline-secret", Severity: SevWarn, Path: path,
				Message: fmt.Sprintf("%s: header %s holds a literal secret in the config file (value not shown)", id, k)})
		}
	}
	auditServerIsolation(r, c, path, s)
	return surfaces
}

func runnerPackage(cmd string, args []string) (pkg string, pinned bool) {
	rest := args
	switch {
	case runners[cmd]:
	case (cmd == "pnpm" || cmd == "yarn") && len(args) > 0 && args[0] == "dlx":
		rest = args[1:]
	case cmd == "pipx" && len(args) > 0 && args[0] == "run":
		rest = args[1:]
	case cmd == "uv" && len(args) > 1 && args[0] == "tool" && args[1] == "run":
		rest = args[2:]
	default:
		return "", false
	}
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if strings.HasPrefix(a, "-") {
			if (a == "--from" || a == "-p" || a == "--package") && i+1 < len(rest) {
				return rest[i+1], pkgPinned(rest[i+1])
			}
			continue
		}
		return a, pkgPinned(a)
	}
	return "", false
}

func pkgPinned(p string) bool {
	if strings.HasPrefix(p, ".") || strings.HasPrefix(p, "/") || strings.Contains(p, "://") || strings.HasPrefix(p, "git+") {
		return true // local path / explicit URL: not a registry fetch-by-name
	}
	if strings.Contains(p, "==") {
		return true
	}
	name := strings.TrimPrefix(p, "@")
	i := strings.LastIndex(name, "@")
	if i < 0 {
		return false
	}
	ver := name[i+1:]
	if ver == "" || ver == "latest" || ver == "next" || strings.ContainsAny(ver, "^~*x><") {
		return false
	}
	return true
}

func containsAny(list []string, vals ...string) bool {
	for _, a := range list {
		for _, v := range vals {
			if a == v {
				return true
			}
		}
	}
	return false
}

func hasArgPrefix(list []string, subs ...string) bool {
	for _, a := range list {
		for _, s := range subs {
			if strings.Contains(a, s) {
				return true
			}
		}
	}
	return false
}

// auditAgentSettings looks at approval / sandbox settings of agent CLIs.
func auditAgentSettings(r *resolved, c *collector, path string, doc map[string]any) []ExecSurface {
	var surfaces []ExecSurface
	base := filepath.Base(path)
	// Claude Code settings.json
	if perms, ok := doc["permissions"].(map[string]any); ok {
		if m, _ := perms["defaultMode"].(string); m == "bypassPermissions" {
			c.add(Finding{Rule: "agent.approval-bypass", Severity: SevWarn, Path: path,
				Message: "permissions.defaultMode = bypassPermissions: every tool call (shell, file writes, network) runs without confirmation",
				Fix:     "use the default mode, or run bypass mode only inside a disposable container"})
			surfaces = append(surfaces, ExecSurface{Path: path, Kind: "approval-bypass",
				Why: "permissions.defaultMode = bypassPermissions: every tool call runs without confirmation"})
		}
		for _, a := range strList(perms["allow"]) {
			if a == "Bash" || a == "Bash(*)" || a == "Bash(*:*)" {
				c.add(Finding{Rule: "agent.approval-bypass", Severity: SevWarn, Path: path, Message: fmt.Sprintf("permissions.allow contains %q: arbitrary shell commands run without confirmation", a)})
				surfaces = append(surfaces, ExecSurface{Path: path, Kind: "approval-bypass",
					Why: fmt.Sprintf("permissions.allow contains %q: arbitrary shell commands run without confirmation", a)})
			}
		}
	}
	if v, _ := doc["enableAllProjectMcpServers"].(bool); v {
		c.add(Finding{Rule: "mcp.auto-enable-project", Severity: SevWarn, Path: path,
			Message: "enableAllProjectMcpServers = true: any repository's .mcp.json is started without asking (a cloned or downloaded repo can run commands)",
			Fix:     "remove it and approve project MCP servers individually"})
		surfaces = append(surfaces, ExecSurface{Path: path, Kind: "approval-bypass",
			Why: "enableAllProjectMcpServers = true: project MCP servers start without asking"})
	}
	// VS Code / Cursor settings.json
	if v, ok := doc["chat.tools.autoApprove"].(bool); ok && v {
		c.add(Finding{Rule: "agent.approval-bypass", Severity: SevWarn, Path: path, Message: "chat.tools.autoApprove = true: agent tool calls run without confirmation"})
		surfaces = append(surfaces, ExecSurface{Path: path, Kind: "approval-bypass",
			Why: "chat.tools.autoApprove = true: agent tool calls run without confirmation"})
	}
	// Codex config.toml
	if base == "config.toml" {
		ap, _ := doc["approval_policy"].(string)
		sm, _ := doc["sandbox_mode"].(string)
		if ap == "never" || sm == "danger-full-access" {
			sev := SevWarn
			if ap == "never" && sm == "danger-full-access" {
				sev = SevFail
			}
			c.add(Finding{Rule: "agent.approval-bypass", Severity: sev, Path: path,
				Message: fmt.Sprintf("codex approval_policy=%q sandbox_mode=%q: commands run without approval and/or without the sandbox", ap, sm),
				Fix:     "use approval_policy = \"on-request\" and sandbox_mode = \"workspace-write\" on the host"})
			surfaces = append(surfaces, ExecSurface{Path: path, Kind: "approval-bypass",
				Why: fmt.Sprintf("codex approval_policy=%q sandbox_mode=%q", ap, sm)})
		}
		if projects, ok := doc["projects"].(map[string]any); ok {
			for dir, v := range projects {
				pm, _ := v.(map[string]any)
				if tl, _ := pm["trust_level"].(string); tl == "trusted" {
					if d, bad := r.isUntrustedDir(expand(dir, r.home, "")); bad {
						c.add(Finding{Rule: "agent.trusted-untrusted-dir", Severity: SevFail, Path: path,
							Message: fmt.Sprintf("codex marks %s as trusted, but it is inside untrusted location %s", dir, d),
							Fix:     "remove that [projects] entry"})
					}
				}
			}
		}
	}
	auditIsolation(r, c, path, doc)
	return surfaces
}

// stripJSONC removes // and /* */ comments and trailing commas (VS Code
// style settings) while leaving string contents intact.
func stripJSONC(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		ch := b[i]
		if inStr {
			out = append(out, ch)
			switch {
			case esc:
				esc = false
			case ch == '\\':
				esc = true
			case ch == '"':
				inStr = false
			}
			continue
		}
		if ch == '"' {
			inStr = true
			out = append(out, ch)
			continue
		}
		if ch == '/' && i+1 < len(b) && b[i+1] == '/' {
			for i < len(b) && b[i] != '\n' {
				i++
			}
			out = append(out, '\n')
			continue
		}
		if ch == '/' && i+1 < len(b) && b[i+1] == '*' {
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i++
			continue
		}
		out = append(out, ch)
	}
	// trailing commas
	res := make([]byte, 0, len(out))
	inStr, esc = false, false
	for i := 0; i < len(out); i++ {
		ch := out[i]
		if inStr {
			res = append(res, ch)
			switch {
			case esc:
				esc = false
			case ch == '\\':
				esc = true
			case ch == '"':
				inStr = false
			}
			continue
		}
		if ch == '"' {
			inStr = true
		}
		if ch == ',' {
			j := i + 1
			for j < len(out) && (out[j] == ' ' || out[j] == '\t' || out[j] == '\n' || out[j] == '\r') {
				j++
			}
			if j < len(out) && (out[j] == '}' || out[j] == ']') {
				continue
			}
		}
		res = append(res, ch)
	}
	return res
}
