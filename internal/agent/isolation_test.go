package agent

import (
	"path/filepath"
	"strings"
	"testing"
)

// proj returns a trusted working directory inside the polygon with its own
// .git so the default repo scope still walks it.
func (e *env) proj(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(e.polygon, name)
	write(t, filepath.Join(dir, ".git", "HEAD"), "ref: refs/heads/main\n", 0o644)
	return dir
}

func TestCodexApprovalMatrixCritical(t *testing.T) {
	e := newEnv(t)
	cwd := e.proj(t, "svc")
	write(t, filepath.Join(cwd, ".codex", "config.toml"),
		"approval_policy = \"never\"\nsandbox_mode = \"danger-full-access\"\n", 0o644)
	rep := e.run(t, e.policy(), cwd, false)
	f := mustHave(t, rep, "agent.sandbox-approval-matrix", "config.toml", SevFail)
	if !strings.Contains(f.Message, "CRITICAL") {
		t.Fatalf("want CRITICAL wording, got %q", f.Message)
	}
}

func TestCodexApprovalMatrixNeverOnly(t *testing.T) {
	e := newEnv(t)
	cwd := e.proj(t, "svc")
	write(t, filepath.Join(cwd, ".codex", "config.toml"),
		"approval_policy = \"never\"\nsandbox_mode = \"workspace-write\"\n", 0o644)
	rep := e.run(t, e.policy(), cwd, false)
	mustHave(t, rep, "agent.sandbox-approval-matrix", "config.toml", SevWarn)
}

func TestCodexApprovalMatrixSafe(t *testing.T) {
	e := newEnv(t)
	cwd := e.proj(t, "svc")
	write(t, filepath.Join(cwd, ".codex", "config.toml"),
		"approval_policy = \"on-request\"\nsandbox_mode = \"workspace-write\"\n", 0o644)
	rep := e.run(t, e.policy(), cwd, false)
	mustNot(t, rep, "agent.sandbox-approval-matrix", "config.toml")
}

func TestSrtSettingsNoIsolation(t *testing.T) {
	e := newEnv(t)
	cwd := e.proj(t, "svc")
	write(t, filepath.Join(cwd, ".srt-settings.json"), `{
  "allowAppleEvents": true,
  "enableWeakerNetworkIsolation": true,
  "network": {"allowedDomains": ["*"]},
  "filesystem": {"allowWrite": ["/"], "denyRead": []}
}`, 0o644)
	rep := e.run(t, e.policy(), cwd, false)
	if len(find(rep, "agent.no-isolation", ".srt-settings.json")) < 3 {
		t.Fatalf("expected several agent.no-isolation findings, got:\n%s", dump(rep))
	}
	mustHave(t, rep, "agent.no-isolation", ".srt-settings.json", SevFail) // allowAppleEvents
}

func TestSrtSettingsWorkspaceOnlyClean(t *testing.T) {
	e := newEnv(t)
	cwd := e.proj(t, "svc")
	write(t, filepath.Join(cwd, ".srt-settings.json"), `{
  "network": {"allowedDomains": ["api.github.com", "*.github.com"]},
  "filesystem": {"denyRead": ["~/.ssh"], "allowWrite": ["."], "denyWrite": [".env"]}
}`, 0o644)
	rep := e.run(t, e.policy(), cwd, false)
	mustNot(t, rep, "agent.no-isolation", ".srt-settings.json")
}

func TestMCPNoIsolationAndSecretInArgs(t *testing.T) {
	e := newEnv(t)
	cwd := e.proj(t, "svc")
	write(t, filepath.Join(cwd, ".mcp.json"), `{
  "mcpServers": {
    "weather": {"command": "npx", "args": ["-y", "weather-mcp@1.2.3", "--api-key", "sk-livetokenABCDEF123456"]}
  }
}`, 0o644)
	rep := e.run(t, e.policy(), cwd, false)
	mustHave(t, rep, "mcp.no-isolation", ".mcp.json", SevWarn)
	mustHave(t, rep, "mcp.secrets-in-env", ".mcp.json", SevFail)
}

func TestMCPWrappedWithSrtNoWarning(t *testing.T) {
	e := newEnv(t)
	cwd := e.proj(t, "svc")
	write(t, filepath.Join(cwd, ".mcp.json"), `{
  "mcpServers": {
    "fs": {"command": "srt", "args": ["npx", "-y", "@modelcontextprotocol/server-filesystem@1.0.0"]}
  }
}`, 0o644)
	rep := e.run(t, e.policy(), cwd, false)
	mustNot(t, rep, "mcp.no-isolation", ".mcp.json")
}

func TestBypassFlagInConfig(t *testing.T) {
	e := newEnv(t)
	cwd := e.proj(t, "svc")
	write(t, filepath.Join(cwd, ".claude", "settings.json"),
		`{"hooks": {"SessionStart": [{"command": "claude --dangerously-skip-permissions"}]}}`, 0o644)
	rep := e.run(t, e.policy(), cwd, false)
	mustHave(t, rep, "agent.no-isolation", "settings.json", SevFail)
}
