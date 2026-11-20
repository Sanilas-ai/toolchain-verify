package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestHookBinding(t *testing.T) {
	e := newEnv(t)
	cwd := e.proj(t, "hooks")
	write(t, filepath.Join(e.home, ".claude", "settings.json"), `{"permissions":{"defaultMode":"default"}}`, 0o600)
	rep := e.run(t, e.policy(), cwd, true)
	mustHave(t, rep, "agent.hook-missing", "settings.json", SevFail)

	write(t, filepath.Join(e.home, ".claude", "settings.json"),
		`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo nope"}]}]}}`, 0o600)
	rep = e.run(t, e.policy(), cwd, true)
	mustHave(t, rep, "agent.hook-substituted", "settings.json", SevFail)

	write(t, filepath.Join(e.home, ".claude", "settings.json"),
		`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"toolchain-verify policy check --hook claude"}]}]}}`, 0o600)
	rep = e.run(t, e.policy(), cwd, true)
	mustNot(t, rep, "agent.hook-missing", "settings.json")
	mustNot(t, rep, "agent.hook-substituted", "settings.json")
}

func TestTranscriptPerms(t *testing.T) {
	e := newEnv(t)
	cwd := e.proj(t, "sessions")
	dir := filepath.Join(e.home, ".claude", "projects")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rep := e.run(t, e.policy(), cwd, true)
	if runtime.GOOS == "windows" {
		mustNot(t, rep, "cred.transcript-perms", "projects")
		return
	}
	mustHave(t, rep, "cred.transcript-perms", "projects", SevFail)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	rep = e.run(t, e.policy(), cwd, true)
	mustNot(t, rep, "cred.transcript-perms", "projects")
}

func TestInstructionPin(t *testing.T) {
	e := newEnv(t)
	cwd := e.proj(t, "pin")
	write(t, filepath.Join(cwd, "AGENTS.md"), "do the task\n", 0o644)
	opt := Options{Home: e.home, Cwd: cwd, NoHostInventory: true, NoBuiltinAdvisories: true,
		Getenv: func(string) string { return "" }}
	pins, extra, err := CollectInstructions(e.policy(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if len(extra) != 0 || len(pins) != 1 || pins[0].Path != "AGENTS.md" {
		t.Fatalf("pins %+v extra %+v", pins, extra)
	}
	lock := filepath.Join(t.TempDir(), "instructions.lock.json")
	if err := WriteInstructionLock(lock, pins); err != nil {
		t.Fatal(err)
	}
	opt.InstructionLock = lock
	uid := os.Getuid()
	opt.UID = &uid
	rep, err := Run(e.policy(), opt)
	if err != nil {
		t.Fatal(err)
	}
	mustNot(t, rep, "instr.drift", "")
	write(t, filepath.Join(cwd, "AGENTS.md"), "do something else\n", 0o644)
	rep, err = Run(e.policy(), opt)
	if err != nil {
		t.Fatal(err)
	}
	mustHave(t, rep, "instr.drift", "AGENTS.md", SevFail)
}

func TestAdvisoryAge(t *testing.T) {
	e := newEnv(t)
	cwd := e.proj(t, "db")
	adv := filepath.Join(t.TempDir(), "old.toml")
	if err := os.WriteFile(adv, []byte("schema = 1\nupdated = \"2020-01-01\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := e.policy()
	off := false
	p.BuiltinAdvisories = &off
	p.Advisories = []string{adv}
	rep := e.run(t, p, cwd, true)
	mustHave(t, rep, "policy.db-stale", "advisories.toml", SevWarn)

	p.DBMaxAgeDays = -1
	rep = e.run(t, p, cwd, true)
	mustNot(t, rep, "policy.db-stale", "")
}
