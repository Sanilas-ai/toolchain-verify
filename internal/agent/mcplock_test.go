package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func collect(t *testing.T, e *env, cwd string) []LockedServer {
	t.Helper()
	uid := os.Getuid()
	servers, err := CollectMCPServers(e.policy(), Options{Home: e.home, Cwd: cwd, UID: &uid,
		Getenv: func(k string) string { return e.vars[k] }, NoHostInventory: true})
	if err != nil {
		t.Fatal(err)
	}
	return servers
}

func findRule(fs []Finding, rule string) *Finding {
	for i := range fs {
		if fs[i].Rule == rule {
			return &fs[i]
		}
	}
	return nil
}

func TestMCPLockDiscoverAndPin(t *testing.T) {
	e := newEnv(t)
	cwd := e.proj(t, "svc")
	write(t, filepath.Join(cwd, ".mcp.json"), `{
  "mcpServers": {
    "pinned": {"command": "npx", "args": ["-y", "server-a@1.0.0"]},
    "loose":  {"command": "uvx", "args": ["server-b"]}
  }
}`, 0o644)
	servers := collect(t, e, cwd)
	if len(servers) != 2 {
		t.Fatalf("want 2 servers, got %d: %+v", len(servers), servers)
	}
	lock := NewMCPLock(servers, "")

	// Clean check: only the unpinned server warns.
	fs := CheckMCPLock(lock, servers)
	if findRule(fs, "mcp.lock") != nil {
		t.Fatalf("unexpected drift on a clean check: %+v", fs)
	}
	if up := findRule(fs, "mcp.lock-unpinned"); up == nil {
		t.Fatalf("expected mcp.lock-unpinned for the uvx server: %+v", fs)
	}

	// Version drift on the pinned server.
	drift := append([]LockedServer(nil), servers...)
	for i := range drift {
		if drift[i].Name == "pinned" {
			drift[i].Version = "9.9.9"
			drift[i].Integrity = specHash("npx", []string{"-y", "server-a@9.9.9"}, "")
		}
	}
	fs = CheckMCPLock(lock, drift)
	d := findRule(fs, "mcp.lock")
	if d == nil || d.Severity != SevFail {
		t.Fatalf("expected mcp.lock FAIL on version drift: %+v", fs)
	}
}

func TestMCPLockNewAndRemoved(t *testing.T) {
	e := newEnv(t)
	cwd := e.proj(t, "svc")
	write(t, filepath.Join(cwd, ".mcp.json"), `{
  "mcpServers": {"a": {"command": "node", "args": ["srv.js"]}}
}`, 0o644)
	servers := collect(t, e, cwd)
	lock := NewMCPLock(servers, "")
	// Lock references a server that is no longer present.
	lock.Servers["ghost"] = MCPLockEntry{Integrity: "deadbeef"}
	// A newly added server not in the lock.
	extra := append(servers, LockedServer{Key: "b", Name: "b", Path: "x", Command: "node", Integrity: "feed"})
	fs := CheckMCPLock(lock, extra)
	if findRule(fs, "mcp.lock-new") == nil {
		t.Fatalf("expected mcp.lock-new: %+v", fs)
	}
	if findRule(fs, "mcp.lock-removed") == nil {
		t.Fatalf("expected mcp.lock-removed: %+v", fs)
	}
}

func TestParseNameVersion(t *testing.T) {
	cases := []struct{ in, n, v string }{
		{"pkg@1.2.3", "pkg", "1.2.3"},
		{"@scope/pkg@1.2.3", "@scope/pkg", "1.2.3"},
		{"pkg==1.2.3", "pkg", "1.2.3"},
		{"pkg", "pkg", ""},
		{"@scope/pkg", "@scope/pkg", ""},
	}
	for _, c := range cases {
		n, v := parseNameVersion(c.in)
		if n != c.n || v != c.v {
			t.Errorf("parseNameVersion(%q) = (%q,%q); want (%q,%q)", c.in, n, v, c.n, c.v)
		}
	}
}
