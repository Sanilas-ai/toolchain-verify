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

func TestSampleManifestParses(t *testing.T) {
	if _, err := manifest.Parse([]byte(sample)); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"../../examples/toolchain.toml", "../../examples/oss-sandbox.toml"} {
		if _, err := manifest.Load(f); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func TestInitAndCheck(t *testing.T) {
	dir := t.TempDir()
	mf := filepath.Join(dir, "toolchain.toml")
	var out, errb bytes.Buffer
	if code := run([]string{"init", "-m", mf}, &out, &errb); code != 0 {
		t.Fatalf("init: %d %s", code, errb.String())
	}
	if code := run([]string{"init", "-m", mf}, &out, &errb); code != 2 {
		t.Fatalf("init over existing file should fail, got %d", code)
	}

	bin := filepath.Join(dir, "bin")
	os.Mkdir(bin, 0o755)
	os.WriteFile(filepath.Join(bin, "hello"), []byte("#!/bin/sh\necho hello 2.1.0\n"), 0o755)
	os.WriteFile(mf, []byte("[[tool]]\nname = \"hello\"\nversion = \"^2\"\n"), 0o644)

	out.Reset()
	if code := run([]string{"check", "-m", mf, "--root", dir, "--json"}, &out, &errb); code != 0 {
		t.Fatalf("check: exit %d\n%s", code, out.String())
	}
	var rep struct {
		OK    bool
		Tools []struct{ Name, Status, Version string }
	}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if !rep.OK || rep.Tools[0].Version != "2.1.0" {
		t.Errorf("unexpected report: %+v", rep)
	}

	os.WriteFile(mf, []byte("[[tool]]\nname = \"hello\"\nversion = \">=3\"\n"), 0o644)
	out.Reset()
	if code := run([]string{"check", "-m", mf, "--root", dir}, &out, &errb); code != 1 {
		t.Fatalf("check should fail with 1, got %d", code)
	}
	if !strings.Contains(out.String(), "does not satisfy") {
		t.Errorf("human output missing reason:\n%s", out.String())
	}
	if code := run([]string{"check", "-m", filepath.Join(dir, "nope.toml")}, &out, &errb); code != 2 {
		t.Errorf("missing manifest should exit 2, got %d", code)
	}
}
