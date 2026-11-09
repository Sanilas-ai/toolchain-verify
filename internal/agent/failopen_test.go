package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreSessionNoTrustedRootsIncomplete(t *testing.T) {
	e := newEnv(t)
	uid := os.Getuid()
	// Safe cwd (not Downloads), but no trusted roots: previously PASS.
	// TempDir lives under /tmp (an untrusted location). Allow it so we can
	// observe the no-trusted-roots Incomplete path without exit 3.
	rep, err := RunPreSession(&Policy{InventoryPaths: []string{e.polygon}}, Options{
		Home: e.home, Cwd: e.polygon, InContainer: true, UID: &uid, NoHostInventory: true,
		NoBuiltinAdvisories: true, AllowUntrustedCwd: true, Getenv: func(string) string { return "" },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Incomplete {
		t.Fatalf("expected Incomplete; findings:\n%s", dump(rep))
	}
	mustHave(t, rep, "policy.no-trusted-roots", "", SevWarn)
	if rep.OK == false {
		// OK may still be true (WARN only); Incomplete is the gate.
	}
	// With trusted roots configured, pre-session of a trusted cwd is complete.
	rep2, err := RunPreSession(e.policy(), Options{
		Home: e.home, Cwd: e.polygon, InContainer: true, UID: &uid, NoHostInventory: true,
		NoBuiltinAdvisories: true, AllowUntrustedCwd: true, Getenv: func(string) string { return "" },
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep2.Incomplete {
		t.Fatalf("trusted pre-session should be complete:\n%s", dump(rep2))
	}
	mustNot(t, rep2, "policy.no-trusted-roots", "")
}

func TestTrustedScopeDefaultsToRepo(t *testing.T) {
	e := newEnv(t)
	other := filepath.Join(e.polygon, "other-repo")
	cur := filepath.Join(e.polygon, "current-repo")
	os.MkdirAll(filepath.Join(other, ".git"), 0o755)
	os.MkdirAll(filepath.Join(cur, ".git"), 0o755)
	write(t, filepath.Join(other, "AGENTS.md"), "other only", 0o664)
	write(t, filepath.Join(cur, "AGENTS.md"), "current", 0o664)

	uid := os.Getuid()
	opt := Options{Home: e.home, Cwd: cur, InContainer: true, UID: &uid, NoHostInventory: true,
		NoBuiltinAdvisories: true, Getenv: func(string) string { return "" }}
	p := e.policy() // trusted = ~/open-source-polygon

	// Default scope=repo: only current-repo is walked for instr.writable.
	rep, err := Run(p, opt)
	if err != nil {
		t.Fatal(err)
	}
	mustHave(t, rep, "instr.writable", filepath.Join("current-repo", "AGENTS.md"), SevInfo)
	mustNot(t, rep, "instr.writable", filepath.Join("other-repo", "AGENTS.md"))
	for _, s := range rep.Scanned {
		if strings.Contains(s, "other-repo") {
			t.Fatalf("default scope walked other-repo: %v", rep.Scanned)
		}
	}

	// Explicit trusted-roots restores the old full walk.
	opt.Scope = "trusted-roots"
	rep2, err := Run(p, opt)
	if err != nil {
		t.Fatal(err)
	}
	mustHave(t, rep2, "instr.writable", filepath.Join("other-repo", "AGENTS.md"), SevInfo)
	mustHave(t, rep2, "instr.writable", filepath.Join("current-repo", "AGENTS.md"), SevInfo)
}

func TestEditorSettingsWritableOnlyWithMCPKeys(t *testing.T) {
	e := newEnv(t)
	eslintOnly := filepath.Join(e.polygon, "app", ".vscode", "settings.json")
	write(t, eslintOnly, `{
  "eslint.options": {
    "overrideConfigFile": "config/eslint.config.mjs"
  }
}`, 0o664)
	withMCP := filepath.Join(e.polygon, "mcp-app", ".vscode", "settings.json")
	write(t, withMCP, `{
  "mcp": {
    "servers": {
      "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "."]}
    }
  }
}`, 0o664)

	uid := os.Getuid()
	// Run from polygon so both projects are under the trusted root; use
	// trusted-roots so the walk sees both settings files via projectMCPConfigs
	// (cwd-relative) — place them under cwd.
	cwd := e.polygon
	// projectMCPConfigs looks at cwd/.vscode/settings.json only. Put the
	// eslint-only file there, and also feed the MCP one via agent.mcp_configs.
	write(t, filepath.Join(cwd, ".vscode", "settings.json"), `{
  "eslint.options": {"overrideConfigFile": "config/eslint.config.mjs"}
}`, 0o664)

	p := e.policy()
	p.MCPConfigs = []string{withMCP}
	rep, err := Run(p, Options{Home: e.home, Cwd: cwd, InContainer: true, UID: &uid,
		NoHostInventory: true, NoBuiltinAdvisories: true, Scope: "repo",
		Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	mustNot(t, rep, "mcp.writable", filepath.Join(cwd, ".vscode", "settings.json"))
	mustNot(t, rep, "mcp.writable", "eslint")
	mustHave(t, rep, "mcp.writable", withMCP, SevInfo)
}

func TestHasMCPKeys(t *testing.T) {
	if hasMCPKeys(map[string]any{"eslint.options": map[string]any{}}) {
		t.Fatal("eslint-only should be false")
	}
	if !hasMCPKeys(map[string]any{"mcpServers": map[string]any{}}) {
		t.Fatal("mcpServers should be true")
	}
	if !hasMCPKeys(map[string]any{"chat.mcp.access": "any"}) {
		t.Fatal("chat.mcp.* should be true")
	}
	if !hasMCPKeys(map[string]any{"mcp.server.foo": true}) {
		t.Fatal("mcp.* should be true")
	}
	if !isEditorSettingsPath("/x/.vscode/settings.json") {
		t.Fatal(".vscode/settings.json")
	}
	if isEditorSettingsPath("/x/.mcp.json") {
		t.Fatal(".mcp.json is not editor settings")
	}
}
