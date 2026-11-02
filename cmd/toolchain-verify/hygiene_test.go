package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sanilas-ai/toolchain-verify/internal/manifest"
)

func TestHygieneManifestParses(t *testing.T) {
	m, err := manifest.Load("../../examples/hygiene-hp.toml")
	if err != nil {
		t.Fatal(err)
	}
	if m.ExecLint == nil || m.Docker == nil {
		t.Fatal("expected [exec_lint] and [docker]")
	}
	if _, err := manifest.Parse([]byte("[exec_lint]\nmode = \"block\"\n")); err == nil {
		t.Error("invalid exec_lint.mode must be rejected")
	}
	if _, err := manifest.Parse([]byte("[docker]\nsocekt = \"/x\"\n")); err == nil {
		t.Error("unknown docker key must be rejected")
	}
}

func TestExecLintCLI(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "agent.py"), []byte("import subprocess\nimport openai\nsubprocess.run(reply, shell=True)\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "ok.py"), []byte("import subprocess\nsubprocess.run(['make'])\n"), 0o644)
	var out, errb bytes.Buffer
	if code := run([]string{"exec-lint", "-m", "../../examples/hygiene-hp.toml", dir}, &out, &errb); code != 0 {
		t.Fatalf("report mode: exit %d\n%s%s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "exec.unwrapped") || !strings.Contains(out.String(), "agent.py:3") {
		t.Errorf("output: %s", out.String())
	}
	out.Reset()
	if code := run([]string{"exec-lint", "-m", "../../examples/hygiene-hp.toml", "--fail", "--json", dir}, &out, &errb); code != 1 {
		t.Fatalf("--fail: exit %d", code)
	}
	var rep struct {
		Mode     string
		Findings []struct{ Rule, Severity string }
	}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil || rep.Mode != "fail" || len(rep.Findings) != 1 || rep.Findings[0].Severity != "fail" {
		t.Errorf("json: %v %+v", err, rep)
	}
	out.Reset()
	if code := run([]string{"exec-lint", "-m", "../../examples/hygiene-hp.toml", "-q", filepath.Join(dir, "ok.py")}, &out, &errb); code != 0 || out.Len() != 0 {
		t.Errorf("-q on pass: exit %d out %q", code, out.String())
	}
	home, _ := os.UserHomeDir()
	if code := run([]string{"exec-lint", "-m", "../../examples/hygiene-hp.toml", home}, &out, &errb); code != 2 {
		t.Errorf("home as lint root must be refused (exit 2), got %d", code)
	}
}

func TestDockerCLI(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"docker", "-m", "../../examples/hygiene-hp.toml", "--socket", "off", "--json"}, &out, &errb); code > 1 {
		t.Fatalf("socket off: exit %d %s", code, errb.String())
	}
	if !strings.Contains(out.String(), `"containers": 0`) {
		t.Errorf("json: %s", out.String())
	}
	if code := run([]string{"docker", "--socket", "rel.sock"}, &out, &errb); code != 2 {
		t.Errorf("relative socket: exit %d", code)
	}
	if code := run([]string{"docker", "--socket", "/nonexistent/x.sock", "--require-engine", "-m", "../../examples/hygiene-hp.toml"}, &out, &errb); code != 1 {
		t.Errorf("--require-engine without engine: exit %d", code)
	}
}
