package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestArgsHardenedDefaults(t *testing.T) {
	args, err := Args(Config{Image: "python:3.12-slim@sha256:abc", Stdin: true,
		Mounts: []Mount{{Source: "/home/u/proj", Target: "/work"}}, Env: []string{"LANG=C"}}, "python3", "-")
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Join(args, " ")
	for _, want := range []string{"run --rm", "--network none", "--read-only", "--cap-drop ALL",
		"--security-opt no-new-privileges", "--user 65534:65534", "--ipc none", "--pids-limit 128",
		"--memory 512m --memory-swap 512m", "--tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m", "-i",
		"--mount type=bind,source=/home/u/proj,target=/work,ro", "--workdir /work", "--env LANG=C",
		"python:3.12-slim@sha256:abc python3 -"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in %s", want, s)
		}
	}
	if strings.Contains(s, "--privileged") {
		t.Error("privileged")
	}
}

func TestArgsRefusals(t *testing.T) {
	for name, c := range map[string]Config{
		"no image":   {},
		"flag image": {Image: "--privileged"},
		"root":       {Image: "x", User: "root"},
		"uid0":       {Image: "x", User: "0:0"},
		"sock":       {Image: "x", Mounts: []Mount{{Source: "/var/run/docker.sock", Target: "/s"}}},
		"root mount": {Image: "x", Mounts: []Mount{{Source: "/", Target: "/h"}}},
		"rel mount":  {Image: "x", Mounts: []Mount{{Source: "proj", Target: "/w"}}},
		"comma":      {Image: "x", Mounts: []Mount{{Source: "/a,readonly=false", Target: "/w"}}},
		"bad env":    {Image: "x", Env: []string{"--privileged"}},
		"not pinned": {Image: "python:3.12", RequireDigest: true},
	} {
		if _, err := Args(c, "true"); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := Args(Config{}, "x"); !errors.Is(err, ErrNoImage) {
		t.Error("ErrNoImage")
	}
	if _, err := Command(context.Background(), Config{Image: "x", Runtime: "sh"}); !errors.Is(err, ErrUnsafe) {
		t.Error("runtime must be docker or podman")
	}
	cmd, err := Command(context.Background(), Config{Image: "x"}, "true")
	if err != nil || filepath.Base(cmd.Args[0]) != "docker" || len(cmd.Env) != 1 {
		t.Errorf("command: %v %v", cmd, err)
	}
}

// TestRunIsolatedScript runs the shipped shell wrapper with a fake docker
// on PATH that only prints its arguments.
func TestRunIsolatedScript(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	script, _ := filepath.Abs("../examples/sandbox/run-isolated.sh")
	bin := t.TempDir()
	os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0o755)
	proj := t.TempDir()
	run := func(env []string, args ...string) (string, error) {
		cmd := exec.Command(bash, append([]string{script}, args...)...)
		cmd.Env = append([]string{"PATH=" + bin + ":/usr/bin:/bin", "HOME=/nonexistent"}, env...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	out, err := run([]string{"TV_SANDBOX_IMAGE=python:3.12-slim@sha256:abc"}, "--mount", proj, "--", "python3", "-c", "print(1)")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	got := strings.Join(strings.Fields(out), " ")
	for _, want := range []string{"run --rm", "--network none", "--read-only", "--cap-drop ALL", "--user 65534:65534",
		"--security-opt no-new-privileges", "type=bind,source=" + proj + ",target=/work,ro", "python:3.12-slim@sha256:abc python3 -c print(1)"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
	if out, err := run(nil, "--", "true"); err == nil {
		t.Errorf("missing image must fail: %s", out)
	}
	if out, err := run([]string{"TV_SANDBOX_IMAGE=x@sha256:1"}, "--mount", "/", "--", "true"); err == nil {
		t.Errorf("mounting / must fail: %s", out)
	}
	if out, _ := run([]string{"TV_SANDBOX_IMAGE=python:3.12"}, "--", "true"); !strings.Contains(out, "not pinned") {
		t.Errorf("unpinned image must warn: %s", out)
	}
}
