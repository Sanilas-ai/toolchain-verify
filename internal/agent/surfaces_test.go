package agent

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestRequireContainerListsSurfaces(t *testing.T) {
	e := newEnv(t)
	write(t, filepath.Join(e.home, ".cursor", "mcp.json"), `{
  "mcpServers": {
    "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]},
    "trusted": {"command": "uvx", "args": ["mcp-server-fetch"], "autoApprove": ["fetch"]}
  }
}`, 0o600)

	rep := e.run(t, e.policy(), e.polygon, false)
	f := mustHave(t, rep, "policy.require-container", "", SevWarn)
	if !strings.Contains(f.Message, "stdio-mcp") || !strings.Contains(f.Message, "approval-bypass") {
		t.Fatalf("WARN must list surface kinds; got: %s", f.Message)
	}
	if !strings.Contains(f.Message, "mcp.json") {
		t.Fatalf("WARN must name the config path; got: %s", f.Message)
	}
	if len(rep.ExecSurfaces) < 2 {
		t.Fatalf("ExecSurfaces=%d, want >= 2: %+v", len(rep.ExecSurfaces), rep.ExecSurfaces)
	}
	kinds := map[string]bool{}
	for _, s := range rep.ExecSurfaces {
		kinds[s.Kind] = true
		if s.Path == "" || s.Why == "" {
			t.Fatalf("incomplete surface: %+v", s)
		}
		mustHave(t, rep, "policy.exec-surface", s.Path, SevInfo)
	}
	if !kinds["stdio-mcp"] || !kinds["approval-bypass"] {
		t.Fatalf("kinds=%v", kinds)
	}

	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"exec_surfaces"`) || !strings.Contains(string(b), `"stdio-mcp"`) {
		t.Fatalf("JSON missing exec_surfaces: %s", b)
	}

	sarif, err := json.Marshal(rep.SARIF("test"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sarif), `"policy.exec-surface"`) {
		t.Fatalf("SARIF missing policy.exec-surface: %s", sarif)
	}
	if !strings.Contains(string(sarif), "mcp.json") {
		t.Fatalf("SARIF missing surface path: %s", sarif)
	}
}

func TestRequireContainerInContainerNoWarn(t *testing.T) {
	e := newEnv(t)
	write(t, filepath.Join(e.home, ".cursor", "mcp.json"), `{
  "mcpServers": {
    "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]}
  }
}`, 0o600)

	rep := e.run(t, e.policy(), e.polygon, true)
	for _, f := range rep.Findings {
		if f.Rule == "policy.require-container" && f.Severity == SevWarn {
			t.Fatalf("in-container run must not WARN on require-container: %+v", f)
		}
	}
	f := mustHave(t, rep, "policy.require-container", "", SevInfo)
	if !strings.Contains(f.Message, "already running in a container") {
		t.Fatalf("INFO note missing: %s", f.Message)
	}
	if !strings.Contains(f.Message, "stdio-mcp") {
		t.Fatalf("INFO must still list surfaces: %s", f.Message)
	}
	if len(rep.ExecSurfaces) == 0 {
		t.Fatal("ExecSurfaces empty")
	}
	if !rep.OK {
		t.Fatalf("in-container INFO should not fail the run: %s", dump(rep))
	}
}
