package agent

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestMCPBlocklistedAndReviewed(t *testing.T) {
	e := newEnv(t)
	write(t, filepath.Join(e.home, ".cursor", "mcp.json"), `{
  "mcpServers": {
    "karma": {"command": "npx", "args": ["-y", "karma365-mcp@2.1.0"]},
    "dyn": {"command": "uvx", "args": ["dynamic-mcp==1.0.9"]},
    "tv": {"command": "uv", "args": ["tool", "run", "--from", "Teamviewer_MCP_Server", "tv"]},
    "local": {"command": "npx", "args": ["-y", "evil-helper-mcp@1.0.0"]},
    "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2026.1.14", "/tmp"]},
    "fetch": {"command": "uvx", "args": ["mcp-server-fetch==2026.1.3"]}
  }
}`, 0o600)
	p := e.policy()
	p.MCPDenylist = []string{"evil-helper-mcp"}
	p.MCPReviewed = []string{"@modelcontextprotocol/server-filesystem@2026.1.14"}
	rep := e.run(t, p, e.polygon, true)
	got := map[string]bool{}
	for _, f := range find(rep, "mcp.blocklisted-package", "mcp.json") {
		if f.Severity != SevFail {
			t.Errorf("want fail: %+v", f)
		}
		for _, n := range []string{"karma365-mcp", "dynamic-mcp", "Teamviewer_MCP_Server", "evil-helper-mcp"} {
			if strings.Contains(f.Message, `"`+n+`"`) {
				got[n] = true
			}
		}
		if strings.Contains(f.Message, "server-filesystem") || strings.Contains(f.Message, "mcp-server-fetch") {
			t.Errorf("benign server blocklisted: %s", f.Message)
		}
	}
	if len(got) != 4 {
		t.Fatalf("blocklisted servers found: %v; findings: %+v", got, rep.Findings)
	}
	nr := find(rep, "mcp.not-reviewed", "mcp.json")
	if len(nr) != 1 || !strings.Contains(nr[0].Message, "mcp-server-fetch==2026.1.3") || nr[0].Severity != SevWarn {
		t.Fatalf("mcp.not-reviewed: %+v", nr)
	}

	// Without mcp_reviewed the review rule is off; the blocklist still applies.
	rep = e.run(t, e.policy(), e.polygon, true)
	mustNot(t, rep, "mcp.not-reviewed", "")
	if n := len(find(rep, "mcp.blocklisted-package", "mcp.json")); n != 3 {
		t.Fatalf("builtin blocklist hits = %d, want 3", n)
	}
}

func TestPkgName(t *testing.T) {
	for in, want := range map[string]string{
		"@scope/pkg@1.2.3": "@scope/pkg", "@scope/pkg": "@scope/pkg", "pkg==1.0": "pkg",
		"pkg[cli]>=2": "pkg", "pkg@latest": "pkg", "pkg": "pkg",
	} {
		if got := pkgName(in); got != want {
			t.Errorf("pkgName(%q) = %q, want %q", in, got, want)
		}
	}
	if mcpDenyKey("Teamviewer_MCP.Server==0.0.1") != "teamviewer-mcp-server" {
		t.Error("pypi normalisation")
	}
}
