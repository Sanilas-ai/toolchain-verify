package hostsec

// apps group: developer-workstation AI/IDE software (2T threat intel,
// 2026-11-13 / 2026-11-15). Read-only; nothing is executed. Versions come
// from files on disk or from command output passed in with flags.

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
	"github.com/Sanilas-ai/toolchain-verify/internal/version"
)

// AppsPolicy is [host.apps].
type AppsPolicy struct {
	// ExtensionDenylist adds IDE extensions to the built-in list:
	// "publisher.name@1.2.3" or "publisher.name@*" (any version).
	ExtensionDenylist []string `toml:"extension_denylist"`
}

type badExtension struct {
	id, version, why string
	refs             []string
}

// builtinBadExtensions are known-malicious IDE extension builds.
var builtinBadExtensions = []badExtension{
	{"anthropic.claude-code", "2.1.312", "tampered copy served by the Cursor marketplace on 2026-10-29 (persistent SSH backdoor: attacker key in authorized_keys, reverse tunnel, LaunchAgent/scheduled-task persistence)",
		[]string{"https://cursor.com/blog/claude-code-extension-security-notice", "https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/"}},
	{"anthropic.claude-code", "2.1.313", "tampered copy served by the Cursor marketplace on 2026-10-29 (persistent SSH backdoor; Anthropic never published 2.1.313)",
		[]string{"https://cursor.com/blog/claude-code-extension-security-notice", "https://www.stepsecurity.io/blog/claude-code-extension-trojanized"}},
}

// sshIOCLabels are public key comments planted by known campaigns. Only the
// file and line are reported, never the key.
var sshIOCLabels = []string{"svc-telemetry"}

// ParseExtensionSpec parses "publisher.name@version" / "publisher.name@*".
func ParseExtensionSpec(s string) (id, ver string, err error) {
	id, ver, ok := strings.Cut(strings.TrimSpace(s), "@")
	if !ok || !strings.Contains(id, ".") || ver == "" {
		return "", "", fmt.Errorf("extension %q: want publisher.name@version or publisher.name@*", s)
	}
	return strings.ToLower(id), ver, nil
}

var (
	extDirRe   = regexp.MustCompile(`(?i)^([a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9._-]*?)-(\d+\.\d+\.\d+)(?:-[a-z0-9_-]+)?$`)
	llamaNumRe = regexp.MustCompile(`(?i)version:\s*(\d+)\s*\(`)
	llamaSemRe = regexp.MustCompile(`(?i)version:\s*v?(\d+\.\d+\.\d+)`)
	llamaTagRe = regexp.MustCompile(`\bb(\d{3,6})\b`)
)

// Fixed builds / versions.
const (
	llamaSSRFFixBuild = 12340 // llama.cpp b12340: llama-server SSRF (CORS proxy, media URLs)
	vscodeFixed       = "1.145.3"
)

var extensionDirs = []string{".vscode/extensions", ".vscode-server/extensions", ".vscode-insiders/extensions", ".vscode-oss/extensions",
	".cursor/extensions", ".cursor-server/extensions", ".windsurf/extensions", ".windsurf-server/extensions"}

func homeDirs(e *env) []string {
	out := []string{"/root"}
	return append(out, e.glob("/home/*")...)
}

func checkApps(e *env, opt Options, p *Policy, c *findings.Collector) {
	checkVSCode(e, opt, c)
	checkLlama(e, opt, c)
	checkExtensions(e, p, c)
	checkSSHIOC(e, c)
}

// ---- VS Code: CVE-2026-120779 (MCP elicitation notification -> command link) ----

func checkVSCode(e *env, opt Options, c *findings.Collector) {
	type src struct{ where, ver string }
	var found []src
	if len(opt.VSCodeVersion) > 0 {
		first, _, _ := strings.Cut(strings.TrimSpace(string(opt.VSCodeVersion)), "\n")
		found = append(found, src{"code --version", strings.TrimSpace(first)})
	} else {
		files := []string{"/usr/share/code/resources/app/package.json", "/opt/visual-studio-code/resources/app/package.json",
			"/snap/code/current/usr/share/code/resources/app/package.json", "/usr/lib/code/package.json"}
		for _, h := range homeDirs(e) {
			files = append(files, e.glob(path.Join(h, ".vscode-server/bin/*/package.json"))...)
		}
		for _, f := range files {
			b, err := e.read(f)
			if err != nil {
				continue
			}
			var pj struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			}
			if json.Unmarshal(b, &pj) != nil || pj.Version == "" || (pj.Name != "" && pj.Name != "code-oss-dev" && pj.Name != "code") {
				continue
			}
			found = append(found, src{f, pj.Version})
		}
	}
	fixed, _ := version.Parse(vscodeFixed)
	for _, s := range found {
		v, err := version.Parse(s.ver)
		if err != nil {
			c.Add(findings.Finding{Rule: "host.vscode-cve-2026-120779", Severity: findings.SevInfo, Path: s.where, Message: "cannot parse VS Code version " + strconv.Quote(s.ver)})
			continue
		}
		if version.Compare(v, fixed) < 0 {
			c.Add(findings.Finding{Rule: "host.vscode-cve-2026-120779", Severity: findings.SevFail, Path: s.where, CWE: cwe("CWE-94"),
				Message: fmt.Sprintf("VS Code %s < %s: a malicious MCP server can turn an elicitation notification into a one-click command link (CVE-2026-120779, CVSS 9.6)", v, vscodeFixed),
				Fix:     "update VS Code to 1.145.3 or later; until then connect only to trusted MCP servers and do not click links in their notifications",
				Refs:    []string{"https://github.com/microsoft/vscode/security/advisories/GHSA-66hq-jw93-462h", "https://nvd.nist.gov/vuln/detail/cve-2026-120779"}})
		}
	}
}

// ---- llama.cpp / llama-server ----

// LlamaBuild extracts the llama.cpp build number or semantic version from
// `llama-server --version` output ("version: 12340 (8954f19)" or
// "version: 1.0.0 (...)").
func LlamaBuild(out string) (build int, sem string) {
	if m := llamaNumRe.FindStringSubmatch(out); m != nil {
		build, _ = strconv.Atoi(m[1])
		return build, ""
	}
	if m := llamaSemRe.FindStringSubmatch(out); m != nil {
		return 0, m[1]
	}
	if m := llamaTagRe.FindStringSubmatch(out); m != nil {
		build, _ = strconv.Atoi(m[1])
	}
	return build, ""
}

func checkLlama(e *env, opt Options, c *findings.Collector) {
	refs := []string{"https://github.com/ggml-org/llama.cpp/releases/tag/b12340", "https://github.com/ggml-org/llama.cpp/releases/tag/v1.0.0"}
	if len(opt.LlamaVersion) == 0 {
		for _, b := range []string{"/usr/local/bin/llama-server", "/usr/bin/llama-server", "/opt/llama.cpp/bin/llama-server"} {
			if e.exists(b) {
				c.Add(findings.Finding{Rule: "host.llama-server-stale", Severity: findings.SevInfo, Path: b,
					Message: "llama-server is installed; pass `llama-server --version` output with --llama-version to check it against the SSRF/CORS/DNS-rebinding fixes"})
			}
		}
		return
	}
	build, sem := LlamaBuild(string(opt.LlamaVersion))
	switch {
	case sem != "":
		v, err := version.Parse(sem)
		if err == nil && v.Major >= 1 {
			return
		}
		c.Add(findings.Finding{Rule: "host.llama-server-stale", Severity: findings.SevWarn, Path: "llama-server --version",
			Message: "unrecognised llama.cpp version " + strconv.Quote(sem), Refs: refs})
	case build == 0:
		c.Add(findings.Finding{Rule: "host.llama-server-stale", Severity: findings.SevWarn, Path: "llama-server --version",
			Message: "no llama.cpp build number found in the --llama-version input"})
	case build < llamaSSRFFixBuild:
		c.Add(findings.Finding{Rule: "host.llama-server-stale", Severity: findings.SevFail, Path: "llama-server --version", CWE: cwe("CWE-918", "CWE-346", "CWE-350"),
			Message: fmt.Sprintf("llama.cpp build b%d < b%d: llama-server's CORS proxy and media URLs reach loopback/LAN (SSRF, incl. via redirects and DNS rebinding) and --cors-origins / Host checks are weak", build, llamaSSRFFixBuild),
			Fix:     "upgrade to llama.cpp v1.0.0 or later (also cancels MCP tool calls on disconnect/timeout); keep llama-server on 127.0.0.1 and do not pass --media-allow-private-urls or --allow-unauthenticated-tools",
			Refs:    refs})
	default:
		c.Add(findings.Finding{Rule: "host.llama-server-stale", Severity: findings.SevInfo, Path: "llama-server --version",
			Message: fmt.Sprintf("llama.cpp build b%d has the SSRF fix; v1.0.0 adds MCP tool-call cancellation on disconnect/timeout and the DNS-rebinding Host check (note: v1.0.0 removes the deprecated C API)", build),
			Refs:    refs})
	}
}

// ---- IDE extensions ----

func checkExtensions(e *env, p *Policy, c *findings.Collector) {
	deny := append([]badExtension(nil), builtinBadExtensions...)
	if p.Apps != nil {
		for _, s := range p.Apps.ExtensionDenylist {
			id, ver, err := ParseExtensionSpec(s)
			if err == nil {
				deny = append(deny, badExtension{id: id, version: ver, why: "listed in host.apps.extension_denylist"})
			}
		}
	}
	for _, h := range homeDirs(e) {
		for _, d := range extensionDirs {
			dir := path.Join(h, d)
			names, err := openDir(e.path(dir))
			if err != nil {
				continue
			}
			for _, n := range names {
				m := extDirRe.FindStringSubmatch(n)
				if m == nil {
					continue
				}
				id, ver := strings.ToLower(m[1]), m[2]
				for _, b := range deny {
					if b.id == id && (b.version == "*" || b.version == ver) {
						c.Add(findings.Finding{Rule: "host.ide-extension-denylist", Severity: findings.SevFail, Path: path.Join(dir, n), CWE: cwe("CWE-506", "CWE-829"),
							Message: fmt.Sprintf("IDE extension %s %s is on the denylist: %s", id, ver, b.why),
							Fix:     "remove the extension, then check authorized_keys (host.authorized-keys-baseline), cron/systemd user units and autostart for persistence; uninstalling alone may not remove it. Rotate credentials reachable from this host",
							Refs:    b.refs})
					}
				}
			}
		}
	}
}

// ---- SSH: public IoC key labels and the authorized_keys baseline ----

type keyAccount struct{ user, home string }

func keyAccounts(e *env) []keyAccount {
	accts := []keyAccount{{"root", "/root"}}
	for _, p := range readPasswd(e) {
		if p.uid == 0 && p.home == "/root" {
			continue
		}
		if p.uid == 0 || (p.uid >= 1000 && p.uid < 65534 && loginShell(p.shell) && p.home != "" && p.home != "/") {
			accts = append(accts, keyAccount{p.user, p.home})
		}
	}
	return accts
}

type keyLine struct {
	user, at, blob string
	fields         []string
}

func liveKeys(e *env) []keyLine {
	var out []keyLine
	for _, a := range keyAccounts(e) {
		for _, name := range []string{".ssh/authorized_keys", ".ssh/authorized_keys2"} {
			p := path.Join(a.home, name)
			b, err := e.read(p)
			if err != nil {
				continue
			}
			for i, raw := range strings.Split(string(b), "\n") {
				l := strings.TrimSpace(raw)
				if l == "" || l[0] == '#' {
					continue
				}
				if _, typ, blob := splitKeyLine(l); typ != "" {
					out = append(out, keyLine{a.user, p + ":" + strconv.Itoa(i+1), blob, strings.Fields(l)})
				}
			}
		}
	}
	return out
}

func checkSSHIOC(e *env, c *findings.Collector) {
	for _, k := range liveKeys(e) {
		for _, f := range k.fields {
			for _, ioc := range sshIOCLabels {
				if f == ioc || strings.HasPrefix(f, ioc+"@") {
					c.Add(findings.Finding{Rule: "host.ssh-ioc-key", Severity: findings.SevFail, Path: k.at, CWE: cwe("CWE-506"),
						Message: k.user + ": authorized key carries the comment " + strconv.Quote(ioc) + ", planted by the trojanized Claude Code extension (2026-10-29); key not shown",
						Fix:     "remove the line, look for the reverse-tunnel persistence (cron, systemd --user, autostart, LaunchAgents) and rotate credentials from a trusted machine",
						Refs:    []string{"https://cursor.com/blog/claude-code-extension-security-notice"}})
				}
			}
		}
	}
}

// checkKeysBaseline fails every authorized key that is not in the baseline
// (an authorized_keys-format file of the keys that are supposed to be
// there). Only file:line is reported, never the key or its fingerprint.
func checkKeysBaseline(e *env, baseline []byte, c *findings.Collector) {
	known := map[string]bool{}
	for _, l := range strings.Split(string(baseline), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || l[0] == '#' {
			continue
		}
		if _, typ, blob := splitKeyLine(l); typ != "" {
			known[blob] = true
		}
	}
	if len(known) == 0 {
		c.Add(findings.Finding{Rule: "host.authorized-keys-baseline", Severity: findings.SevWarn, Path: "--authorized-keys-baseline",
			Message: "the baseline contains no keys; every authorized key will be reported"})
	}
	for _, k := range liveKeys(e) {
		if !known[k.blob] {
			c.Add(findings.Finding{Rule: "host.authorized-keys-baseline", Severity: findings.SevFail, Path: k.at, CWE: cwe("CWE-284", "CWE-506"),
				Message: k.user + ": authorized key is not in the baseline (an unexpected key is how SSH backdoors persist); key and fingerprint not shown",
				Fix:     "if you did not add it, remove it and investigate; if you did, add it to the baseline file"})
		}
	}
}
