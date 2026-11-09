package reposcan

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// Approval and trust switches that turn a repo config into code execution
// without a prompt. Keys are compared case-insensitively against the last
// path element; values must be truthy.
var bypassKeys = map[string]string{
	"enableallprojectmcpservers":        "Claude Code: approve every MCP server in this repo",
	"autoapprove":                       "MCP/VS Code: tool calls run without confirmation",
	"alwaysallow":                       "Cline/Roo: tool calls run without confirmation",
	"chat.tools.autoapprove":            "VS Code: all agent tool calls auto-approved",
	"chat.tools.global.autoapprove":     "VS Code: all agent tool calls auto-approved",
	"autoaccept":                        "Gemini CLI: auto-accept tool calls",
	"yolo":                              "agent YOLO mode",
	"trust":                             "Gemini CLI: trusted MCP server (no confirmation)",
	"dangerouslyskippermissions":        "Claude Code: permissions disabled",
	"skipdangerousmodepermissionprompt": "Claude Code: dangerous-mode prompt disabled",
}

var bypassValues = map[string]string{
	"bypasspermissions":  "Claude Code permission mode bypassPermissions",
	"yolo":               "approval mode yolo",
	"never":              "approval policy never",
	"danger-full-access": "sandbox disabled",
}

var endpointKeys = regexp.MustCompile(`(?i)^(anthropic_base_url|anthropic_api_url|openai_base_url|openai_api_base|gemini_api_base|google_gemini_base_url|azure_openai_endpoint|http_proxy|https_proxy|all_proxy|node_options|ld_preload|pythonstartup|pythonpath|bash_env)$`)

func (s *scanner) scanJSONConfig(rel, kind string, b []byte) {
	root, dups, err := parseJSONC(b)
	for _, d := range dups {
		sev := SevWarn
		if kind != KindEditorConfig {
			sev = SevFail
		}
		s.add(Finding{Rule: "config.duplicate-key", Severity: sev, Path: rel, Line: d.line, Evidence: escapeEvidence(d.key, 80),
			Message: "duplicate key: clients disagree on which value wins (first/last), so the reviewed value may not be the one loaded",
			Fix:     "keep exactly one occurrence"})
	}
	if err != nil {
		s.incomplete(rel + ": cannot parse: " + err.Error())
		s.add(Finding{Rule: "config.parse-error", Severity: SevWarn, Path: rel, Message: "config could not be parsed (" + err.Error() + "); its effect is unknown",
			Fix: "fix the syntax; a client with a lenient parser may still load parts of it"})
		return
	}
	// Approval bypass / endpoint override / secrets anywhere in the tree.
	root.walkStrings(nil, func(p []string, n *jnode) {
		if len(p) == 0 {
			return
		}
		last := strings.ToLower(p[len(p)-1])
		if hasSecret(n.str) {
			s.add(Finding{Rule: "secret.in-config", Severity: SevFail, Path: rel, Line: n.line, Evidence: escapeEvidence(n.str, 100),
				Message: "credential stored in an agent/editor config (" + strings.Join(p, ".") + "); committed configs leak it to every clone",
				Fix:     "rotate the credential, then remove it; reference an env var or a secret store instead",
				Refs:    []string{"https://thehackernews.com/2026/11/claude-codes-dont-ask-again-file.html"}})
		}
		if why, ok := bypassValues[strings.ToLower(n.str)]; ok && (last == "defaultmode" || last == "approvalmode" || last == "approval_policy" || last == "sandbox_mode" || last == "mode") {
			s.add(Finding{Rule: "agent.approval-bypass", Severity: SevFail, Path: rel, Line: n.line, Evidence: strings.Join(p, ".") + " = " + escapeEvidence(n.str, 40),
				Message: "repository config disables agent approvals: " + why})
		}
		if endpointKeys.MatchString(last) && n.str != "" && inEnvBlock(p) {
			s.add(Finding{Rule: "agent.endpoint-override", Severity: SevFail, Path: rel, Line: n.line, Evidence: strings.Join(p, ".") + " = " + escapeEvidence(n.str, 100),
				Message: "repository config sets " + strings.ToUpper(last) + " for the agent/MCP process: traffic, prompts and tokens can be redirected or code injected"})
		}
	})
	walkAll(root, nil, func(p []string, n *jnode) {
		if len(p) == 0 || (n.kind != jBool && n.kind != jString && n.kind != jArray && n.kind != jObject) {
			return
		}
		last := strings.ToLower(p[len(p)-1])
		joined := strings.ToLower(strings.Join(p, "."))
		why, ok := bypassKeys[last]
		if !ok {
			why, ok = bypassKeys[joined]
		}
		if ok && n.truthy() && n.kind != jObject {
			s.add(Finding{Rule: "agent.approval-bypass", Severity: SevFail, Path: rel, Line: n.line, Evidence: strings.Join(p, "."),
				Message: "repository config disables confirmations: " + why,
				Fix:     "remove it; approvals belong in the user's own (not the repo's) settings"})
		}
		if last == "task.allowautomatictasks" && n.kind == jString && strings.EqualFold(n.str, "on") {
			s.add(Finding{Rule: "editor.auto-tasks", Severity: SevFail, Path: rel, Line: n.line, Evidence: "task.allowAutomaticTasks = on",
				Message: "workspace allows tasks to run automatically on folder open without asking"})
		}
		if last == "security.workspace.trust.enabled" && n.kind == jBool && n.str == "false" {
			s.add(Finding{Rule: "editor.trust-disabled", Severity: SevFail, Path: rel, Line: n.line, Evidence: "security.workspace.trust.enabled = false",
				Message: "workspace config tries to disable VS Code Workspace Trust"})
		}
	})

	// MCP servers.
	for _, key := range []string{"mcpServers", "servers", "mcp.servers", "context_servers", "mcp"} {
		for _, srvs := range root.get(key, true) {
			if key == "mcp" {
				for _, inner := range srvs.get("servers", true) {
					s.mcpServers(rel, inner)
				}
				continue
			}
			s.mcpServers(rel, srvs)
		}
	}
	// Hooks (Claude/Gemini/Cursor/Codex style): every "command" string
	// below a "hooks" key.
	for _, h := range root.get("hooks", true) {
		h.walkStrings([]string{"hooks"}, func(p []string, n *jnode) {
			if !strings.EqualFold(p[len(p)-1], "command") && !strings.EqualFold(p[len(p)-1], "bash") {
				return
			}
			event := "hook"
			if len(p) >= 2 {
				event = p[1]
			}
			s.judgeCommand(rel, n.line, "agent.hook", "repository-supplied "+event+" hook runs automatically when the agent session starts/acts", n.str, nil)
		})
	}
	// Claude "permissions.allow" rules that captured secrets are covered by
	// secret.in-config; broad allow rules are reported here.
	for _, perms := range root.get("permissions", true) {
		for _, allow := range perms.get("allow", true) {
			for _, e := range allow.elems {
				if e.kind != jString {
					continue
				}
				v := strings.TrimSpace(e.str)
				if v == "Bash" || v == "Bash(*)" || v == "Bash(*:*)" || strings.EqualFold(v, "*") {
					s.add(Finding{Rule: "agent.broad-permission", Severity: SevFail, Path: rel, Line: e.line, Evidence: escapeEvidence(v, 60),
						Message: "repository settings pre-approve any shell command for the agent"})
				}
			}
		}
	}
	// VS Code tasks.
	if kind == KindEditorTasks {
		for _, tasks := range root.get("tasks", false) {
			for _, t := range tasks.elems {
				s.vscodeTask(rel, t)
			}
		}
	}
	// package.json in a config-ish location is handled by scanPackageHook.
}

func inEnvBlock(p []string) bool {
	for _, e := range p[:len(p)-1] {
		if strings.EqualFold(e, "env") || strings.EqualFold(e, "environment") || strings.EqualFold(e, "terminal.integrated.env.linux") || strings.EqualFold(e, "terminal.integrated.env.osx") {
			return true
		}
	}
	return len(p) == 1 // top-level ANTHROPIC_BASE_URL in some configs
}

// walkAll visits every node with its key path.
func walkAll(n *jnode, p []string, visit func([]string, *jnode)) {
	if n == nil {
		return
	}
	visit(p, n)
	switch n.kind {
	case jObject:
		for _, m := range n.members {
			walkAll(m.val, append(append([]string(nil), p...), m.key), visit)
		}
	case jArray:
		for _, e := range n.elems {
			walkAll(e, p, visit)
		}
	}
}

func (s *scanner) vscodeTask(rel string, t *jnode) {
	runOn := ""
	for _, ro := range t.get("runOptions", false) {
		for _, r := range ro.get("runOn", false) {
			runOn = r.str
		}
	}
	var parts []string
	for _, k := range []string{"command", "args", "script"} {
		for _, v := range t.get(k, false) {
			parts = append(parts, v.strs()...)
		}
	}
	for _, osKey := range []string{"linux", "osx", "windows"} {
		for _, o := range t.get(osKey, false) {
			for _, v := range o.get("command", false) {
				parts = append(parts, v.strs()...)
			}
			for _, v := range o.get("args", false) {
				parts = append(parts, v.strs()...)
			}
		}
	}
	cmd := strings.Join(parts, " ")
	if strings.EqualFold(runOn, "folderOpen") {
		s.judgeCommand(rel, t.line, "editor.folderopen-task", "VS Code task runs automatically when the folder is opened (runOn: folderOpen)", cmd, nil)
	} else if cmd != "" {
		sig := signals(canonical(cmd))
		if r, _ := verdictFor(sig, false); r != "" {
			s.add(Finding{Rule: "editor.risky-task", Severity: SevWarn, Path: rel, Line: t.line, Evidence: escapeEvidence(cmd, evidenceRunes), Signals: sigList(sig),
				Message: "editor task command has a risky pattern (" + r + "); it runs only when invoked"})
		}
	}
}

// judgeCommand reports an auto-run command: warn by default (it runs code
// from the repo without review), fail when it fetches, decodes+executes,
// reads secrets, pipes to a shell, references an IOC or runs a hidden
// script.
func (s *scanner) judgeCommand(rel string, line int, rule, what, cmd string, extra []string) {
	canon := canonical(cmd)
	sig := signals(canon)
	sev := SevWarn
	reasons := []string{}
	if r, _ := verdictFor(sig, true); r != "" && r != "injection.override" {
		sev = SevFail
		reasons = append(reasons, strings.TrimPrefix(r, "injection."))
	}
	if sig[sigNetwork] || sig[sigPipeShell] || sig[sigExfil] {
		sev = SevFail
		reasons = append(reasons, "network")
	}
	if hp := hiddenScriptRef(cmd); hp != "" {
		sev = SevFail
		reasons = append(reasons, "runs script in unusual location "+hp)
	}
	if ioc := s.opt.IOCs.matchText(canon); ioc != "" {
		sev = SevFail
		reasons = append(reasons, "IOC "+ioc)
	}
	reasons = append(reasons, extra...)
	msg := what
	if len(reasons) > 0 {
		msg += " — " + strings.Join(reasons, "; ")
	}
	s.add(Finding{Rule: rule, Severity: sev, Path: rel, Line: line, Evidence: escapeEvidence(cmd, evidenceRunes), Signals: sigList(sig), Message: msg,
		Fix:  "remove it unless you wrote it; auto-run hooks/tasks from a cloned repo execute before you review anything",
		Refs: []string{"https://socket.dev/blog/shai-hulud-descendant-malicious-ruby-gem"}})
	for _, ref := range scriptRefs(cmd) {
		s.refs = append(s.refs, cmdRef{from: rel, cmd: ref, line: line, rule: rule})
	}
}

var scriptRefRe = regexp.MustCompile(`(?:^|[\s"'=])((?:\./|\.\./|/|~/|\$home/|\$\{workspacefolder\}/)?[a-z0-9_.@/-]+\.(?:js|mjs|cjs|ts|py|sh|rb|pl|ps1|bin))\b`)

func scriptRefs(cmd string) []string {
	var out []string
	for _, m := range scriptRefRe.FindAllStringSubmatch(strings.ToLower(cmd), -1) {
		out = append(out, m[1])
	}
	return out
}

// hiddenScriptRef returns a script path under a location where build or
// MCP code does not normally live (.github/, .vscode/, /tmp, ~/.config).
func hiddenScriptRef(cmd string) string {
	for _, r := range scriptRefs(cmd) {
		r2 := strings.TrimPrefix(strings.TrimPrefix(r, "${workspacefolder}/"), "./")
		switch {
		case strings.HasPrefix(r2, ".github/"), strings.HasPrefix(r2, ".vscode/"), strings.HasPrefix(r2, ".cursor/"), strings.HasPrefix(r2, ".claude/"),
			strings.HasPrefix(r2, "/tmp/"), strings.HasPrefix(r2, "/var/tmp/"), strings.HasPrefix(r2, "/dev/shm/"),
			strings.HasPrefix(r2, "~/.config/"), strings.HasPrefix(r2, "$home/.config/"), strings.HasPrefix(r2, "~/.local/"):
			return r
		}
	}
	return ""
}

var containerRunRe = regexp.MustCompile(`\b(docker|podman|nerdctl)\s+(container\s+)?run\b`)

var runnerRe = regexp.MustCompile(`^(npx|uvx|bunx|pnpm|yarn|pipx|uv)$`)

func (s *scanner) mcpServers(rel string, srvs *jnode) {
	if srvs == nil || srvs.kind != jObject {
		return
	}
	for _, m := range srvs.members {
		name, srv := m.key, m.val
		if srv.kind != jObject {
			continue
		}
		var command string
		for _, c := range srv.get("command", true) {
			if c.kind == jString {
				command = c.str
			} else if c.kind == jObject { // zed: {"command":{"path":...,"args":[...]}}
				for _, p := range c.get("path", false) {
					command = p.str
				}
				for _, a := range c.get("args", false) {
					command += " " + strings.Join(a.strs(), " ")
				}
			}
		}
		var args []string
		for _, a := range srv.get("args", true) {
			args = append(args, a.strs()...)
		}
		full := strings.TrimSpace(command + " " + strings.Join(args, " "))
		var urlStr string
		for _, k := range []string{"url", "serverUrl", "httpUrl", "endpoint"} {
			for _, u := range srv.get(k, true) {
				urlStr = u.str
			}
		}
		if full != "" {
			extra := []string{}
			if bin := path.Base(strings.Fields(command + " x")[0]); runnerRe.MatchString(bin) {
				if pkg := firstPkgArg(args); pkg != "" && !pinnedPkg(pkg) {
					extra = append(extra, "unpinned package "+pkg+" (rug pull: new versions run without review)")
				}
				if pkg := firstPkgArg(args); pkg != "" {
					if near := typosquatOf(pkg); near != "" {
						s.add(Finding{Rule: "mcp.typosquat", Severity: SevFail, Path: rel, Line: srv.line, Evidence: escapeEvidence(pkg, 80),
							Message: fmt.Sprintf("MCP package %q is one edit away from the well-known %q", pkg, near)})
					}
				}
			}
			if ioc := s.opt.IOCs.mcpName(name); ioc != "" {
				bin := path.Base(strings.Fields(command + " x")[0])
				if bin == "node" || bin == "bun" || bin == "deno" || bin == "python" || bin == "python3" {
					extra = append(extra, "server name matches IOC "+ioc+" and runs a local script with "+bin)
				}
			}
			s.judgeMCP(rel, srv.line, name, full, extra)
		}
		if urlStr != "" {
			u, err := url.Parse(urlStr)
			switch {
			case err != nil:
				s.add(Finding{Rule: "mcp.bad-url", Severity: SevWarn, Path: rel, Line: srv.line, Evidence: escapeEvidence(urlStr, 100), Message: "MCP server URL does not parse"})
			case u.Scheme == "http" && !isLoopbackHost(u.Hostname()):
				s.add(Finding{Rule: "mcp.remote-cleartext", Severity: SevFail, Path: rel, Line: srv.line, Evidence: escapeEvidence(urlStr, 100),
					Message: "remote MCP server over plain HTTP: tool descriptions and results can be rewritten in transit"})
			case !isLoopbackHost(u.Hostname()):
				s.add(Finding{Rule: "mcp.remote", Severity: SevInfo, Path: rel, Line: srv.line, Evidence: escapeEvidence(urlStr, 100),
					Message: "repository adds remote MCP server " + escapeEvidence(name, 40) + "; its tool descriptions are untrusted input"})
			}
			if u != nil && u.User != nil {
				s.add(Finding{Rule: "secret.in-config", Severity: SevFail, Path: rel, Line: srv.line, Message: "MCP URL carries credentials"})
			}
		}
		for _, env := range srv.get("env", true) {
			for _, e := range env.members {
				if e.val.kind == jString && literalSecretValue(e.key, e.val.str) {
					s.add(Finding{Rule: "secret.in-config", Severity: SevFail, Path: rel, Line: e.line, Evidence: e.key + "=" + escapeEvidence(redact(e.val.str), 30),
						Message: "literal secret in MCP server env"})
				}
			}
		}
	}
}

func (s *scanner) judgeMCP(rel string, line int, name, full string, extra []string) {
	canon := canonical(full)
	sig := signals(canon)
	sev := SevInfo
	reasons := append([]string{}, extra...)
	if len(extra) > 0 {
		sev = SevWarn
	}
	for _, e := range extra {
		if strings.Contains(e, "IOC") {
			sev = SevFail
		}
	}
	if sig[sigPipeShell] || (sig[sigDecode] && sig[sigExec]) || (sig[sigNetwork] && sig[sigExec]) || sig[sigExfil] {
		sev = SevFail
		reasons = append(reasons, "shell bootstrap / download-and-run")
	}
	if hp := hiddenScriptRef(full); hp != "" {
		sev = SevFail
		reasons = append(reasons, "runs script in unusual location "+hp)
	}
	if ioc := s.opt.IOCs.matchText(canon); ioc != "" {
		sev = SevFail
		reasons = append(reasons, "IOC "+ioc)
	}
	if containerRunRe.MatchString(canon) && !strings.Contains(canon, "@sha256:") {
		if sev == SevInfo {
			sev = SevWarn
		}
		reasons = append(reasons, "container image not pinned by digest")
	}
	if strings.Contains(canon, "--privileged") || strings.Contains(canon, "docker.sock") || regexp.MustCompile(`-v\s+/:/`).MatchString(canon) {
		sev = SevFail
		reasons = append(reasons, "container escape (privileged/docker.sock/host root)")
	}
	msg := "repository defines MCP server " + escapeEvidence(name, 40) + "; it starts as a local process when the agent loads this project"
	if len(reasons) > 0 {
		msg += " — " + strings.Join(reasons, "; ")
	}
	s.add(Finding{Rule: "mcp.server", Severity: sev, Path: rel, Line: line, Evidence: escapeEvidence(full, evidenceRunes), Signals: sigList(sig), Message: msg,
		Fix: "approve project MCP servers explicitly (baseline); pin package versions; never auto-enable repo servers"})
	for _, ref := range scriptRefs(full) {
		s.refs = append(s.refs, cmdRef{from: rel, cmd: ref, line: line, rule: "mcp.server"})
	}
}

func firstPkgArg(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--from" || a == "--package" || a == "-p" {
			if i+1 < len(args) {
				return args[i+1]
			}
		}
		if strings.HasPrefix(a, "-") || a == "dlx" || a == "run" || a == "x" || a == "exec" || a == "tool" {
			continue
		}
		return a
	}
	return ""
}

var pinnedRe = regexp.MustCompile(`(@|==)v?\d+\.\d+(\.\d+)?([-.+][0-9A-Za-z.-]+)?$`)

func pinnedPkg(p string) bool {
	if strings.HasPrefix(p, ".") || strings.HasPrefix(p, "/") {
		return true
	}
	return pinnedRe.MatchString(p)
}

// wellKnownMCP are package names worth protecting against near-miss names.
var wellKnownMCP = []string{
	"@modelcontextprotocol/server-filesystem", "@modelcontextprotocol/server-github", "@modelcontextprotocol/server-memory",
	"@modelcontextprotocol/server-everything", "@modelcontextprotocol/server-puppeteer", "@modelcontextprotocol/server-sequential-thinking",
	"@modelcontextprotocol/server-slack", "@modelcontextprotocol/server-postgres", "@modelcontextprotocol/server-brave-search",
	"@playwright/mcp", "@upstash/context7-mcp", "@sentry/mcp-server", "mcp-server-fetch", "mcp-server-git", "mcp-server-time",
	"@browsermcp/mcp", "chrome-devtools-mcp", "@notionhq/notion-mcp-server", "@stripe/mcp", "firecrawl-mcp",
}

func typosquatOf(pkg string) string {
	name := strings.ToLower(pkg)
	if i := strings.LastIndex(name, "@"); i > 0 {
		name = name[:i]
	}
	if j := strings.Index(name, "=="); j > 0 {
		name = name[:j]
	}
	for _, k := range wellKnownMCP {
		if name == k {
			return ""
		}
	}
	for _, k := range wellKnownMCP {
		limit := 1
		if len(k) >= 15 {
			limit = 2
		}
		if d := editDistance(name, k, limit); d >= 1 && d <= limit && len(k) > 6 {
			return k
		}
		// scope swap: @modelcontextprotoco1/server-x
		if strings.Contains(k, "/") && strings.Contains(name, "/") && strings.SplitN(name, "/", 2)[1] == strings.SplitN(k, "/", 2)[1] {
			sa, sb := strings.SplitN(name, "/", 2)[0], strings.SplitN(k, "/", 2)[0]
			if sa != sb && editDistance(sa, sb, 3) <= 2 {
				return k
			}
		}
	}
	return ""
}

// editDistance is Levenshtein distance, stopping early above limit.
func editDistance(a, b string, limit int) int {
	ra, rb := []rune(a), []rune(b)
	if d := len(ra) - len(rb); d > limit || -d > limit {
		return limit + 1
	}
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		best := cur[0]
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			if cur[j] < best {
				best = cur[j]
			}
		}
		if best > limit {
			return limit + 1
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)]
}

func isLoopbackHost(h string) bool {
	h = strings.ToLower(h)
	return h == "localhost" || h == "127.0.0.1" || h == "::1" || strings.HasPrefix(h, "127.")
}

var secretNameRe = regexp.MustCompile(`(?i)(token|secret|password|passwd|api[_-]?key|private[_-]?key|credential|auth)`)

func literalSecretValue(key, val string) bool {
	if hasSecret(val) {
		return true
	}
	if !secretNameRe.MatchString(key) || len(val) < 12 {
		return false
	}
	if strings.Contains(val, "${") || strings.HasPrefix(val, "$") || strings.Contains(val, "{{") || strings.HasPrefix(val, "env:") || strings.HasPrefix(val, "op://") {
		return false
	}
	lv := strings.ToLower(val)
	for _, ph := range []string{"your", "xxx", "changeme", "example", "placeholder", "<", "redacted", "dummy", "test"} {
		if strings.Contains(lv, ph) {
			return false
		}
	}
	return true
}

// scanCodexConfig: .codex/config.toml in a repository.
func (s *scanner) scanCodexConfig(rel string, b []byte) {
	var doc map[string]any
	md, err := toml.Decode(string(b), &doc)
	if err != nil {
		s.incomplete(rel + ": cannot parse: " + err.Error())
		s.add(Finding{Rule: "config.parse-error", Severity: SevWarn, Path: rel, Message: "Codex config could not be parsed: " + err.Error()})
		return
	}
	_ = md
	if v, _ := doc["approval_policy"].(string); strings.EqualFold(v, "never") {
		s.add(Finding{Rule: "agent.approval-bypass", Severity: SevFail, Path: rel, Evidence: `approval_policy = "never"`, Message: "repository Codex config disables approvals"})
	}
	if v, _ := doc["sandbox_mode"].(string); strings.EqualFold(v, "danger-full-access") {
		s.add(Finding{Rule: "agent.approval-bypass", Severity: SevFail, Path: rel, Evidence: `sandbox_mode = "danger-full-access"`, Message: "repository Codex config disables the sandbox"})
	}
	if srvs, ok := doc["mcp_servers"].(map[string]any); ok {
		for name, v := range srvs {
			m, _ := v.(map[string]any)
			cmd, _ := m["command"].(string)
			var args []string
			if a, ok := m["args"].([]any); ok {
				for _, x := range a {
					if xs, ok := x.(string); ok {
						args = append(args, xs)
					}
				}
			}
			s.judgeMCP(rel, 0, name, strings.TrimSpace(cmd+" "+strings.Join(args, " ")), nil)
		}
	}
	if strings.Contains(string(b), "hooks") {
		s.scanTextControl(rel, KindCodexConfig, b)
	}
}

var lifecycleScripts = map[string]bool{"preinstall": true, "install": true, "postinstall": true, "prepare": true, "prepublish": true, "preprepare": true, "postprepare": true, "prepack": false}

// scanPackageHook: install-time code paths of package managers.
func (s *scanner) scanPackageHook(rel string, b []byte) {
	base := strings.ToLower(path.Base(rel))
	switch {
	case base == "package.json":
		root, dups, err := parseJSONC(b)
		for _, d := range dups {
			s.add(Finding{Rule: "config.duplicate-key", Severity: SevWarn, Path: rel, Line: d.line, Evidence: escapeEvidence(d.key, 80),
				Message: "duplicate key in package.json (npm keeps the last one)"})
		}
		if err != nil {
			s.incomplete(rel + ": cannot parse: " + err.Error())
			s.add(Finding{Rule: "config.parse-error", Severity: SevWarn, Path: rel, Message: "package.json could not be parsed: " + err.Error()})
			return
		}
		for _, scripts := range root.get("scripts", false) {
			for _, m := range scripts.members {
				if !lifecycleScripts[m.key] || m.val.kind != jString {
					continue
				}
				s.judgeLifecycle(rel, m.line, "npm "+m.key, m.val.str)
			}
		}
	case base == "extconf.rb":
		s.judgeLifecycle(rel, 1, "RubyGems native-extension extconf.rb (runs on gem install)", string(b))
	case base == "setup.py":
		s.judgeLifecycle(rel, 1, "setup.py (runs on pip install from source)", string(b))
	case base == "binding.gyp":
		s.judgeLifecycle(rel, 1, "node-gyp binding.gyp (runs on npm install)", string(b))
	case strings.HasSuffix(base, ".gemspec"):
		if regexp.MustCompile(`(?m)\.extensions\s*[=<]|^extensions:`).Match(b) {
			s.add(Finding{Rule: "pkg.native-extension", Severity: SevInfo, Path: rel, Message: "gemspec declares a native extension: its extconf.rb runs at install time"})
		}
	case strings.HasSuffix(base, ".pth"):
		for i, ln := range strings.Split(string(b), "\n") {
			t := strings.TrimSpace(ln)
			if strings.HasPrefix(t, "import ") || strings.HasPrefix(t, "import\t") {
				s.judgeLifecycle(rel, i+1, "Python .pth import line (runs at every interpreter start)", t)
			}
		}
	}
}

// judgeSkillScript: scripts bundled with an agent skill run with the
// agent's privileges when the skill is used (Cisco skill-scanner threat
// model). HTTP + subprocess is normal for tools, so only decode->exec,
// secret->network, pipe-to-shell and IOCs fail; download-and-run warns.
// process.env / os.environ alone plus HTTP is not enough for
// skill.secret-exfil — nearly every real skill tool reads env and calls
// an API. Require a strong credential path or named token (see
// strongSecretRead).
func (s *scanner) judgeSkillScript(rel string, b []byte) {
	canon := canonical(string(b))
	sig := signals(canon)
	var rule, sev string
	switch r, _ := verdictFor(sig, false); {
	case r == "injection.secret-exfil":
		if strongSecretRead(canon) {
			rule, sev = "skill.secret-exfil", SevFail
		}
	case r == "injection.decode-exec":
		rule, sev = "skill.decode-exec", SevFail
	case sig[sigPipeShell]:
		rule, sev = "skill.pipe-to-shell", SevFail
	case sig[sigExfil]:
		rule, sev = "skill.exfil-endpoint", SevWarn
	}
	if ioc := s.opt.IOCs.matchText(canon); ioc != "" {
		rule, sev = "skill.ioc", SevFail
	}
	if rule == "" {
		return
	}
	off := firstMatch(canon, sigSecretRead, sigDecode, sigPipeShell, sigExfil, sigNetwork)
	if off < 0 {
		off = 0
	}
	s.add(Finding{Rule: rule, Severity: sev, Path: rel, Line: lineOf([]byte(canon), off), Evidence: escapeEvidence(snippetAround([]byte(canon), off, 140), evidenceRunes),
		Signals: sigList(sig), Message: "script bundled with an agent skill (runs when the skill is used) has a risky pattern",
		Fix:  "review the script; skills from third parties are code, not documentation",
		Refs: []string{"https://github.com/cisco-ai-defense/skill-scanner"}})
}

// judgeLifecycle: install hooks are normal (native builds); report info,
// and fail when the hook downloads, decodes and executes, or touches
// secrets.
func (s *scanner) judgeLifecycle(rel string, line int, what, body string) {
	canon := canonical(body)
	sig := signals(canon)
	sev, rule := SevInfo, "pkg.install-hook"
	var reasons []string
	if sig[sigNetwork] && sig[sigExec] {
		sev, rule = SevFail, "pkg.download-exec"
		reasons = append(reasons, "downloads and executes at install time")
	}
	if r, _ := verdictFor(sig, false); r == "injection.secret-exfil" || r == "injection.decode-exec" {
		sev, rule = SevFail, "pkg."+strings.TrimPrefix(r, "injection.")
		reasons = append(reasons, strings.TrimPrefix(r, "injection."))
	}
	if sig[sigPipeShell] {
		sev, rule = SevFail, "pkg.download-exec"
		reasons = append(reasons, "pipes a download to a shell")
	}
	if ioc := s.opt.IOCs.matchText(canon); ioc != "" {
		sev = SevFail
		reasons = append(reasons, "IOC "+ioc)
	}
	if strings.HasSuffix(rel, ".pth") && sev == SevInfo {
		sev = SevWarn
	}
	msg := what
	if len(reasons) > 0 {
		msg += " — " + strings.Join(reasons, "; ")
	}
	ev := body
	if off := firstMatch(canon, sigNetwork, sigPipeShell, sigDecode, sigExec); off >= 0 && len(body) > evidenceRunes {
		ev = snippetAround([]byte(canon), off, 140)
	}
	s.add(Finding{Rule: rule, Severity: sev, Path: rel, Line: line, Evidence: escapeEvidence(ev, evidenceRunes), Signals: sigList(sig), Message: msg,
		Fix: "install with scripts disabled (npm --ignore-scripts, pip --only-binary) inside the sandbox until reviewed"})
}

// checkRefs: auto-run commands that point at files which match IOC paths
// (e.g. .github/init.js from the strutil-core worm).
func (s *scanner) checkRefs() {
	for _, r := range s.refs {
		p := strings.TrimPrefix(strings.TrimPrefix(r.cmd, "${workspacefolder}/"), "./")
		if id := s.opt.IOCs.pathIOC(p); id != "" && s.present[p] {
			s.add(Finding{Rule: "ioc.persistence", Severity: SevFail, Path: r.from, Line: r.line, Evidence: escapeEvidence(r.cmd, 100),
				Message: "auto-run " + r.rule + " executes " + p + ", a persistence path of " + id,
				Fix:     "treat the clone and the machine that ran it as compromised: isolate first, disable monitors, then rotate credentials from a clean machine (see refs)",
				Refs:    []string{"https://socket.dev/blog/shai-hulud-descendant-malicious-ruby-gem"}})
		}
	}
}
