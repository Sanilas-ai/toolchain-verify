package execlint

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sanilas-ai/toolchain-verify/internal/agent"
	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func find(rep *Report, rule, pathSuffix string) []findings.Finding {
	var out []findings.Finding
	for _, f := range rep.Findings {
		if f.Rule == rule && strings.HasSuffix(f.Path, pathSuffix) {
			out = append(out, f)
		}
	}
	return out
}

func lint(t *testing.T, dir string, p *Policy, fail bool) *Report {
	t.Helper()
	rep, err := Run(p, Options{Home: "/nonexistent-home", Cwd: dir, Paths: []string{dir}, Fail: fail})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

const pyAgent = `import subprocess
from openai import OpenAI

client = OpenAI()

def run(task):
    code = client.chat.completions.create(model="x", messages=[{"role": "user", "content": task}]).choices[0].message.content
    return subprocess.run(["python3", "-c", code], capture_output=True, shell=False)

def run_shell(cmd):
    return subprocess.run(cmd, shell=True)

def evil(code):
    exec(code)
`

func TestUnwrappedPython(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "agent.py", pyAgent)
	rep := lint(t, dir, nil, false)
	un := find(rep, "exec.unwrapped", "agent.py")
	if len(un) != 2 || un[0].Severity != findings.SevWarn || un[0].Line != 8 {
		t.Fatalf("unwrapped: %+v", rep.Findings)
	}
	if !strings.Contains(un[1].Message, "[shell]") || !strings.Contains(un[0].Message, "imports openai") {
		t.Errorf("labels: %+v", un)
	}
	if dc := find(rep, "exec.dynamic-code", "agent.py"); len(dc) != 1 || dc[0].Line != 14 {
		t.Errorf("dynamic-code: %+v", rep.Findings)
	}
	if !rep.OK || rep.LLMFiles != 1 || rep.Sinks != 3 {
		t.Errorf("report mode must pass: ok=%v llm=%d sinks=%d", rep.OK, rep.LLMFiles, rep.Sinks)
	}
	rep = lint(t, dir, nil, true)
	if rep.OK || find(rep, "exec.unwrapped", "agent.py")[0].Severity != findings.SevFail {
		t.Errorf("fail mode must fail")
	}
}

func TestNonLLMFilesAreQuiet(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "build.py", "import subprocess\nsubprocess.run(['make'])\n")
	write(t, dir, "main.go", "package main\nimport \"os/exec\"\nfunc main() { exec.Command(\"git\", \"status\").Run() }\n")
	write(t, dir, "node_modules/x/index.js", "const cp = require('child_process'); const OpenAI = require('openai'); cp.exec(x)\n")
	rep := lint(t, dir, nil, true)
	if len(rep.Findings) != 0 || rep.Sinks != 2 || !rep.OK {
		t.Fatalf("expected no findings: %+v sinks=%d", rep.Findings, rep.Sinks)
	}
}

func TestContainerHardening(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "weak.py", `import subprocess
import anthropic
def run(code):
    return subprocess.run(["docker", "run", "--rm", "--network", "none", "python:3.12", "python3", "-c", code])
`)
	write(t, dir, "good.py", `import subprocess
import anthropic
ARGS = ["docker", "run", "--rm", "--network=none", "--read-only", "--cap-drop", "ALL", "--user", "nobody"]
def run(code):
    return subprocess.run(ARGS + ["python:3.12", "python3", "-c", code])
`)
	write(t, dir, "priv.ts", `import OpenAI from "openai";
import { execFile } from "child_process";
execFile("docker", ["run", "--privileged", "--network", "none", "--read-only", "--cap-drop", "ALL", "--user", "nobody", img]);
`)
	write(t, dir, "sdk.py", `import docker, litellm
c = docker.from_env()
def run(code):
    return c.containers.run("python:3.12", ["python3", "-c", code], network_mode="none", read_only=True, cap_drop=["ALL"], user="nobody")
`)
	rep := lint(t, dir, nil, false)
	w := find(rep, "exec.weak-sandbox", "weak.py")
	if len(w) != 1 || !strings.Contains(w[0].Message, "--read-only, --cap-drop ALL, --user nobody") || strings.Contains(w[0].Message, "--network none") {
		t.Errorf("weak: %+v", rep.Findings)
	}
	if len(find(rep, "exec.wrapped", "good.py")) != 1 || len(find(rep, "exec.weak-sandbox", "good.py")) != 0 {
		t.Errorf("good: %+v", rep.Findings)
	}
	if p := find(rep, "exec.weak-sandbox", "priv.ts"); len(p) != 1 || p[0].Severity != findings.SevFail {
		t.Errorf("privileged must fail even in report mode: %+v", rep.Findings)
	}
	if rep.OK {
		t.Error("privileged container must fail the run")
	}
	if len(find(rep, "exec.weak-sandbox", "sdk.py")) != 0 || len(find(rep, "exec.unwrapped", "sdk.py")) != 0 {
		t.Errorf("docker SDK hardened call should pass: %+v", rep.Findings)
	}
}

func TestWrappersAndAnnotations(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "wrapped.go", `package main

import (
	"context"
	"os/exec"

	"github.com/sashabaranov/go-openai"
	"github.com/Sanilas-ai/toolchain-verify/sandbox"
)

func run(ctx context.Context, code string) {
	cmd, _ := sandbox.Command(ctx, sandbox.Config{Image: img}, "python3", "-c", code)
	_ = cmd.Run()
	_ = openai.NewClient
}

func direct(code string) {
	// toolchain-verify:sandboxed — runs inside the oss sandbox container
	exec.Command("sh", "-c", code).Run()
}

func custom(code string) { exec.Command("my-jail", code).Run() }
`)
	write(t, dir, "tool.mjs", `import { spawn } from "node:child_process";
import Anthropic from "@anthropic-ai/sdk";
spawn("run-isolated", ["--", "node", "-e", out]);
`)
	rep := lint(t, dir, &Policy{Wrappers: []string{"my-jail"}}, true)
	if len(find(rep, "exec.annotated", "wrapped.go")) != 1 {
		t.Errorf("annotation: %+v", rep.Findings)
	}
	if len(find(rep, "exec.wrapped", "wrapped.go")) != 1 || len(find(rep, "exec.wrapped", "tool.mjs")) != 1 {
		t.Errorf("wrapped: %+v", rep.Findings)
	}
	if !rep.OK {
		t.Errorf("all calls are wrapped or annotated: %+v", rep.Findings)
	}
}

func TestJSAndShell(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.js", `const { exec } = require("child_process");
const OpenAI = require("openai");
const re = /x/; re.exec("y");
exec(reply.content);
const f = new Function(reply.content);
`)
	write(t, dir, "b.sh", "#!/bin/sh\nout=$(curl -s https://api.openai.com/v1/chat/completions -d @req.json)\neval \"$out\"\nbash -c \"$out\"\n")
	rep := lint(t, dir, nil, false)
	if u := find(rep, "exec.unwrapped", "a.js"); len(u) != 1 || u[0].Line != 4 {
		t.Errorf("js exec: %+v", rep.Findings)
	}
	if d := find(rep, "exec.dynamic-code", "a.js"); len(d) != 1 || d[0].Line != 5 {
		t.Errorf("js Function: %+v", rep.Findings)
	}
	if len(find(rep, "exec.dynamic-code", "b.sh")) != 1 || len(find(rep, "exec.unwrapped", "b.sh")) != 1 {
		t.Errorf("shell: %+v", rep.Findings)
	}
}

func TestTestsExcludesAndIgnore(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "test_agent.py", pyAgent)
	write(t, dir, "gen/agent.py", pyAgent)
	write(t, dir, "src/agent.py", pyAgent)
	write(t, dir, "a/b/fixtures/agent.py", pyAgent)
	rep := lint(t, dir, &Policy{Exclude: []string{"gen/**", "**/fixtures/**"}, Ignore: []string{"exec.dynamic-code"}}, false)
	if len(find(rep, "exec.unwrapped", "fixtures/agent.py")) != 0 {
		t.Errorf("**/fixtures/** not excluded: %+v", rep.Findings)
	}
	if len(find(rep, "exec.unwrapped", "test_agent.py")) != 0 || len(find(rep, "exec.unwrapped", "gen/agent.py")) != 0 {
		t.Errorf("tests/excludes: %+v", rep.Findings)
	}
	if len(find(rep, "exec.unwrapped", "src/agent.py")) != 2 || len(find(rep, "exec.dynamic-code", "")) != 0 || rep.Ignored != 1 {
		t.Errorf("src: %+v ignored=%d", rep.Findings, rep.Ignored)
	}
	rep = lint(t, dir, &Policy{IncludeTests: true}, false)
	if len(find(rep, "exec.unwrapped", "test_agent.py")) != 2 {
		t.Errorf("include_tests: %+v", rep.Findings)
	}
}

func TestRefusals(t *testing.T) {
	home := t.TempDir()
	for _, p := range []string{"/", home, filepath.Join(home, ".ssh")} {
		_, err := Run(nil, Options{Home: home, Cwd: home, Paths: []string{p}})
		if !errors.Is(err, agent.ErrRefused) {
			t.Errorf("%s: want ErrRefused, got %v", p, err)
		}
	}
	if err := (&Policy{Mode: "block"}).Validate(); err == nil {
		t.Error("bad mode must be rejected")
	}
	rep, err := Run(nil, Options{Home: home, Cwd: home, Paths: []string{filepath.Join(home, "missing")}})
	if err != nil || len(find(rep, "exec.path-missing", "missing")) != 1 {
		t.Errorf("missing path: %v %+v", err, rep)
	}
}
