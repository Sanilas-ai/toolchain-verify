package agent

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Agent sandbox / isolation audit. Inspired by Anthropic's sandbox-runtime
// (srt) dual-isolation model (filesystem + network) and the Codex
// "sandbox mode x approval policy" matrix. These rules are deterministic:
// they read already-parsed config documents and never execute anything.
//
// CWE references:
//
//	CWE-250  Execution with Unnecessary Privileges
//	CWE-862  Missing Authorization
//	CWE-693  Protection Mechanism Failure
//	CWE-16   Configuration
const (
	cweUnnecessaryPriv = "https://cwe.mitre.org/data/definitions/250.html" // CWE-250
	cweMissingAuthz    = "https://cwe.mitre.org/data/definitions/862.html" // CWE-862
	cweProtFailure     = "https://cwe.mitre.org/data/definitions/693.html" // CWE-693
	refSandboxRuntime  = "https://github.com/anthropics/sandbox-runtime"
	refCodexSandbox    = "https://github.com/openai/codex"
)

// bypassFlagRe-style literals searched for in any string value of a config.
var bypassFlags = []string{
	"--dangerously-bypass-approvals-and-sandbox",
	"--dangerously-skip-permissions",
	"--yolo",
}

// auditIsolation adds agent.sandbox-approval-matrix and agent.no-isolation
// findings for an already-parsed agent/sandbox config document. path is the
// config file; doc is its decoded top-level map.
func auditIsolation(r *resolved, c *collector, path string, doc map[string]any) {
	base := filepath.Base(path)

	// A bypass-everything flag baked into any launcher string is always a
	// critical no-isolation finding, wherever it appears in the config.
	if flag, where := findBypassFlag(doc); flag != "" {
		c.add(Finding{Rule: "agent.no-isolation", Severity: SevFail, Path: path,
			Message: fmt.Sprintf("%s disables the sandbox and approvals at once (found in %s); every tool call runs with full host access and no confirmation", flag, where),
			Fix:     "remove the flag; run agents inside a sandbox (sandbox-runtime/srt, a container) with human approval for writes, exec and network",
			Refs:    []string{cweUnnecessaryPriv, refSandboxRuntime}})
	}

	// Codex config.toml: the sandbox_mode x approval_policy matrix.
	if base == "config.toml" {
		codexApprovalMatrix(c, path, doc)
	}

	// Anthropic sandbox-runtime (srt) settings file.
	if isSrtSettings(base, doc) {
		auditSrtSettings(r, c, path, doc)
	}

	// Claude Code settings.json: an explicit sandbox:false disables the OS
	// sandbox even when permissions still prompt.
	if sb, ok := doc["sandbox"].(bool); ok && !sb {
		c.add(Finding{Rule: "agent.no-isolation", Severity: SevWarn, Path: path,
			Message: "sandbox = false: the OS sandbox (filesystem/network isolation) is turned off for this agent",
			Fix:     "enable the sandbox, or run the agent inside a disposable container with an egress allow-list",
			Refs:    []string{cweProtFailure, refSandboxRuntime}})
	}
}

// codexApprovalMatrix models Codex's sandbox_mode x approval_policy grid.
//
//	sandbox_mode \ approval  untrusted/on-request/on-failure   never
//	read-only                 ok                                warn (no human gate)
//	workspace-write           ok                                warn (writes w/o gate)
//	danger-full-access        fail (no FS/net isolation)        FAIL critical
func codexApprovalMatrix(c *collector, path string, doc map[string]any) {
	ap, _ := doc["approval_policy"].(string)
	sm, _ := doc["sandbox_mode"].(string)
	if ap == "" && sm == "" {
		return
	}
	danger := sm == "danger-full-access"
	never := ap == "never"
	var sev, note string
	switch {
	case danger && never:
		sev, note = SevFail, "CRITICAL: no sandbox and no approvals as the default; a prompt injection runs any command on the host"
	case danger:
		sev, note = SevFail, "no filesystem/network isolation (danger-full-access); approvals alone do not contain a hijacked tool call"
	case never:
		sev, note = SevWarn, "no human approval gate (approval_policy=never); commands within the sandbox run unattended"
	default:
		return
	}
	c.add(Finding{Rule: "agent.sandbox-approval-matrix", Severity: sev, Path: path,
		Message: fmt.Sprintf("codex sandbox_mode=%q x approval_policy=%q: %s", orNone(sm), orNone(ap), note),
		Fix:     "use sandbox_mode = \"workspace-write\" with approval_policy = \"on-request\" (or \"untrusted\"); reserve danger-full-access for a disposable container",
		Refs:    []string{cweMissingAuthz, refCodexSandbox}})
}

// isSrtSettings reports whether this looks like an anthropics/sandbox-runtime
// (~/.srt-settings.json) settings file: by name, or by its characteristic
// keys.
func isSrtSettings(base string, doc map[string]any) bool {
	if base == ".srt-settings.json" || base == "srt-settings.json" {
		return true
	}
	for _, k := range []string{"enableWeakerNetworkIsolation", "enableWeakerNestedSandbox", "allowNestedUserNamespaces", "allowAppleEvents"} {
		if _, ok := doc[k]; ok {
			return true
		}
	}
	// network{allowedDomains} + filesystem{allowWrite|denyRead} shape.
	_, hasNet := doc["network"].(map[string]any)
	_, hasFS := doc["filesystem"].(map[string]any)
	return hasNet && hasFS
}

// auditSrtSettings checks an srt settings file for weakened isolation,
// unrestricted network (no proxy allow-list) and unrestricted write paths.
func auditSrtSettings(r *resolved, c *collector, path string, doc map[string]any) {
	// Flags the sandbox-runtime docs call out as removing isolation.
	if b, _ := doc["allowAppleEvents"].(bool); b {
		c.add(Finding{Rule: "agent.no-isolation", Severity: SevFail, Path: path,
			Message: "allowAppleEvents = true: the sandbox no longer provides code-execution isolation (a sandboxed command can launch apps outside the sandbox)",
			Fix:     "set allowAppleEvents = false; never source it from a checked-out repo's config",
			Refs:    []string{cweProtFailure, refSandboxRuntime}})
	}
	if b, _ := doc["enableWeakerNetworkIsolation"].(bool); b {
		c.add(Finding{Rule: "agent.no-isolation", Severity: SevWarn, Path: path,
			Message: "enableWeakerNetworkIsolation = true: opens a data-exfiltration vector through the macOS trustd service",
			Fix:     "leave it off unless a Go TLS client truly needs it",
			Refs:    []string{cweProtFailure, refSandboxRuntime}})
	}
	if b, _ := doc["allowNestedUserNamespaces"].(bool); b {
		c.add(Finding{Rule: "agent.no-isolation", Severity: SevWarn, Path: path,
			Message: "allowNestedUserNamespaces = true: denyWrite and the mandatory denies no longer hold against a sandboxed command on Linux",
			Fix:     "turn it off unless the sandboxed command must create user namespaces of its own",
			Refs:    []string{cweProtFailure, refSandboxRuntime}})
	}
	weakNest, _ := doc["enableWeakerNestedSandbox"].(bool)

	net, _ := doc["network"].(map[string]any)
	fsys, _ := doc["filesystem"].(map[string]any)

	if net != nil {
		allowed := strList(net["allowedDomains"])
		allowAll, _ := net["allowAllUnixSockets"].(bool)
		if containsBroadDomain(allowed) {
			c.add(Finding{Rule: "agent.no-isolation", Severity: SevWarn, Path: path,
				Message: "network.allowedDomains contains a wildcard-all entry: there is effectively no proxy allow-list and the agent can reach any host",
				Fix:     "list exact domains (and :port) the agent needs; an empty allowedDomains denies all network",
				Refs:    []string{cweUnnecessaryPriv, refSandboxRuntime}})
		}
		if allowAll && weakNest {
			c.add(Finding{Rule: "agent.no-isolation", Severity: SevWarn, Path: path,
				Message: "allowAllUnixSockets = true with enableWeakerNestedSandbox = true: the nested-namespace limit is left off",
				Fix:     "avoid allowAllUnixSockets; list specific sockets on macOS",
				Refs:    []string{cweProtFailure, refSandboxRuntime}})
		}
	}
	if fsys != nil {
		for _, w := range srtPathList(fsys["allowWrite"]) {
			if broadWritePath(w, r.home) {
				c.add(Finding{Rule: "agent.no-isolation", Severity: SevWarn, Path: path,
					Message: fmt.Sprintf("filesystem.allowWrite grants a very broad write root %q: a hijacked tool call can modify files far outside the workspace", w),
					Fix:     "allow only the workspace (\".\") and the specific dirs the agent needs to write",
					Refs:    []string{cweUnnecessaryPriv, refSandboxRuntime}})
				break
			}
		}
	}
}

// srtPathList accepts both the plain-string and the {"path":...,"literal":true}
// entry forms that sandbox-runtime allows.
func srtPathList(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return strList(v)
	}
	var out []string
	for _, x := range arr {
		switch e := x.(type) {
		case string:
			out = append(out, e)
		case map[string]any:
			if p, ok := e["path"].(string); ok {
				out = append(out, p)
			}
		}
	}
	return out
}

func containsBroadDomain(domains []string) bool {
	for _, d := range domains {
		d = strings.TrimSpace(d)
		host := d
		if i := strings.LastIndex(d, ":"); i >= 0 && !strings.Contains(d, "]") {
			host = d[:i]
		}
		if host == "*" || host == "*.*" || d == "*" {
			return true
		}
	}
	return false
}

// broadWritePath reports whether an srt allowWrite entry is so broad that it
// defeats workspace isolation.
func broadWritePath(p, home string) bool {
	p = strings.TrimSpace(p)
	switch p {
	case "/", "~", "~/", "$HOME", "/home", "/Users", "**", "/**", "*":
		return true
	}
	clean := p
	if strings.HasPrefix(clean, "~/") {
		clean = filepath.Join(home, clean[2:])
	}
	clean = filepath.Clean(clean)
	if home != "" && clean == filepath.Clean(home) {
		return true
	}
	return false
}

func findBypassFlag(doc map[string]any) (flag, where string) {
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		if flag != "" {
			return
		}
		switch t := v.(type) {
		case string:
			for _, f := range bypassFlags {
				if strings.Contains(t, f) {
					flag, where = f, prefixOr(prefix)
					return
				}
			}
		case []any:
			for _, e := range t {
				walk(prefix, e)
			}
		case map[string]any:
			for k, e := range t {
				np := k
				if prefix != "" {
					np = prefix + "." + k
				}
				walk(np, e)
			}
		}
	}
	walk("", doc)
	return
}

func prefixOr(p string) string {
	if p == "" {
		return "a launcher string"
	}
	return p
}

func orNone(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}

// directRunners launch an MCP server as a plain host process (no sandbox).
var directRunners = map[string]bool{
	"npx": true, "bunx": true, "uvx": true, "pnpx": true, "npm": true, "pnpm": true,
	"yarn": true, "pipx": true, "uv": true, "node": true, "nodejs": true, "deno": true,
	"bun": true, "python": true, "python3": true, "ruby": true, "php": true, "go": true,
	"perl": true, "dotnet": true,
}

// sandboxWrappers isolate whatever they wrap (sandbox-runtime, containers).
var sandboxWrappers = map[string]bool{
	"srt": true, "sandbox-runtime": true, "sandbox-exec": true, "docker": true,
	"podman": true, "firejail": true, "bwrap": true, "bubblewrap": true, "nsjail": true,
}

// auditServerIsolation adds mcp.no-isolation (a stdio MCP server launched as a
// bare host process) and mcp.secrets-in-env (a literal secret on the command
// line, which is world-visible via the process list).
func auditServerIsolation(r *resolved, c *collector, path string, s mcpServer) {
	if s.disabled || s.command == "" {
		return
	}
	id := fmt.Sprintf("server %q", s.name)
	cmd := strings.ToLower(filepath.Base(s.command))

	wrapped := sandboxWrappers[cmd]
	if len(s.args) > 0 {
		if first := strings.ToLower(filepath.Base(s.args[0])); sandboxWrappers[first] {
			wrapped = true
		}
	}
	if !wrapped && directRunners[cmd] {
		c.add(Finding{Rule: "mcp.no-isolation", Severity: SevWarn, Path: path,
			Message: id + ": stdio MCP server runs directly on the host via " + cmd + " with no container or OS sandbox; model-controlled tool calls become unsandboxed process exec",
			Fix:     "run each server in its own container (docker/mcp-gateway: per-server container, secrets from a store, tool filtering) or wrap it with sandbox-runtime (srt) to enforce filesystem/network limits",
			Refs:    []string{cweUnnecessaryPriv, "https://github.com/docker/mcp-gateway"}})
	}

	// A literal secret passed on the command line (argv) is strictly worse
	// than one in env: it is visible in `ps`, /proc and shell history.
	if arg, key := secretInArgs(s.args); arg {
		c.add(Finding{Rule: "mcp.secrets-in-env", Severity: SevFail, Path: path,
			Message: fmt.Sprintf("%s: a literal secret is passed on the command line (flag %s, value not shown); argv is world-visible via the process list", id, key),
			Fix:     "pass secrets through env referencing a variable (${TOKEN}) or an OS keychain / Docker secret, never as a literal argument",
			Refs:    []string{"https://cwe.mitre.org/data/definitions/214.html", "https://cwe.mitre.org/data/definitions/312.html"}})
	}
}

// secretInArgs reports a literal secret given as --flag=value or --flag value
// where the flag names a secret.
func secretInArgs(args []string) (bool, string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			continue
		}
		name := strings.TrimLeft(a, "-")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			k, v := name[:eq], name[eq+1:]
			if secretKeyRe.MatchString(k) && isLiteralSecret(v) {
				return true, "--" + k
			}
			continue
		}
		if secretKeyRe.MatchString(name) && i+1 < len(args) && isLiteralSecret(args[i+1]) {
			return true, "--" + name
		}
	}
	return false, ""
}
