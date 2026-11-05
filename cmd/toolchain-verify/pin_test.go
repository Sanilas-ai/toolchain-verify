package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sanilas-ai/toolchain-verify/internal/check"
	"github.com/Sanilas-ai/toolchain-verify/internal/manifest"
)

const pinScript = "#!/bin/sh\necho hello 2.1.0\n"

func pinFixture(t *testing.T, doc string) (dir, mf string) {
	t.Helper()
	dir = t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "hello"), []byte(pinScript), 0o755); err != nil {
		t.Fatal(err)
	}
	mf = filepath.Join(dir, "toolchain.toml")
	if err := os.WriteFile(mf, []byte(doc), 0o640); err != nil {
		t.Fatal(err)
	}
	return dir, mf
}

func TestPinWritesVersionAndHash(t *testing.T) {
	doc := "# keep me\n[[tool]]\nname = \"hello\" # greeter\nversion = \">=1\"\n\n[exec_lint]\nwrappers = [\"oss-run\"]\n"
	dir, mf := pinFixture(t, doc)
	var out, errb bytes.Buffer
	if code := run([]string{"pin", "-m", mf, "--root", dir}, &out, &errb); code != 0 {
		t.Fatalf("pin: exit %d\n%s%s", code, out.String(), errb.String())
	}
	sum := sha256.Sum256([]byte(pinScript))
	digest := hex.EncodeToString(sum[:])
	got, _ := os.ReadFile(mf)
	want := "# keep me\n[[tool]]\nname = \"hello\" # greeter\nversion = \"2.1.0\"\nsha256 = \"" + digest + "\"\n\n[exec_lint]\nwrappers = [\"oss-run\"]\n"
	if string(got) != want {
		t.Errorf("manifest:\n%s\nwant:\n%s", got, want)
	}
	if st, _ := os.Stat(mf); st.Mode().Perm() != 0o640 {
		t.Errorf("permissions changed: %v", st.Mode().Perm())
	}
	if !strings.Contains(out.String(), "hello.version: >=1 -> 2.1.0") || !strings.Contains(out.String(), "wrote ") {
		t.Errorf("output:\n%s", out.String())
	}

	// The pinned manifest passes check, and a second pin is a no-op.
	out.Reset()
	if code := run([]string{"check", "-m", mf, "--root", dir}, &out, &errb); code != 0 {
		t.Fatalf("check after pin: exit %d\n%s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"pin", "-m", mf, "--root", dir}, &out, &errb); code != 0 || !strings.Contains(out.String(), "up to date") {
		t.Fatalf("second pin: exit %d\n%s", code, out.String())
	}
	if again, _ := os.ReadFile(mf); string(again) != want {
		t.Errorf("no-op pin changed the file:\n%s", again)
	}

	// A replaced binary is caught by check, and pin records the new hash.
	os.WriteFile(filepath.Join(dir, "bin", "hello"), []byte("#!/bin/sh\necho hello 2.2.0\n"), 0o755)
	out.Reset()
	if code := run([]string{"check", "-m", mf, "--root", dir}, &out, &errb); code != 1 {
		t.Fatalf("check with replaced binary should fail, got %d", code)
	}
	out.Reset()
	if code := run([]string{"pin", "-m", mf, "--root", dir, "--version", "caret", "--path"}, &out, &errb); code != 0 {
		t.Fatalf("re-pin: exit %d\n%s%s", code, out.String(), errb.String())
	}
	m, err := manifest.Load(mf)
	if err != nil {
		t.Fatal(err)
	}
	if m.Tools[0].Version != "^2.2.0" || m.Tools[0].Path != filepath.Join(dir, "bin", "hello") || m.Tools[0].SHA256 == digest {
		t.Errorf("re-pinned tool: %+v", m.Tools[0])
	}
	if m.ExecLint == nil {
		t.Error("[exec_lint] section lost")
	}
	out.Reset()
	if code := run([]string{"check", "-m", mf, "--root", dir}, &out, &errb); code != 0 {
		t.Fatalf("check after re-pin: exit %d\n%s", code, out.String())
	}
}

func TestPinOptionsAndFailures(t *testing.T) {
	doc := "[[tool]]\nname = \"hello\"\nversion = \">=1\"\n\n[[tool]]\nname = \"absent\"\noptional = true\n"
	dir, mf := pinFixture(t, doc)
	var out, errb bytes.Buffer

	// --dry-run reports but does not write.
	if code := run([]string{"pin", "-m", mf, "--root", dir, "--dry-run"}, &out, &errb); code != 0 {
		t.Fatalf("dry-run: exit %d\n%s%s", code, out.String(), errb.String())
	}
	if got, _ := os.ReadFile(mf); string(got) != doc || !strings.Contains(out.String(), "dry run") || !strings.Contains(out.String(), "SKIP  absent") {
		t.Errorf("dry-run wrote or misreported:\n%s\n%s", got, out.String())
	}

	// --version keep --no-sha256: nothing to do.
	out.Reset()
	if code := run([]string{"pin", "-m", mf, "--root", dir, "--version", "keep", "--no-sha256"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "up to date") {
		t.Errorf("keep/no-sha256: exit %d\n%s", code, out.String())
	}

	// --tool limits the edit; min mode.
	out.Reset()
	if code := run([]string{"pin", "-m", mf, "--root", dir, "--tool", "hello", "--version", "min", "--no-sha256"}, &out, &errb); code != 0 {
		t.Fatalf("--tool: exit %d\n%s%s", code, out.String(), errb.String())
	}
	if got, _ := os.ReadFile(mf); !strings.Contains(string(got), "version = \">=2.1.0\"") || strings.Contains(string(got), "sha256") {
		t.Errorf("--tool/min result:\n%s", got)
	}

	// Usage errors exit 2.
	for _, args := range [][]string{
		{"pin", "-m", mf, "--root", dir, "--tool", "nope"},
		{"pin", "-m", mf, "--root", dir, "--version", "latest"},
		{"pin", "-m", filepath.Join(dir, "missing.toml")},
		{"pin", "-m", mf, "extra"},
	} {
		errb.Reset()
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("%v: exit %d, want 2 (%s)", args, code, errb.String())
		}
	}

	// A required tool that cannot be found fails and writes nothing.
	bad := "[[tool]]\nname = \"hello\"\n\n[[tool]]\nname = \"absent\"\n"
	os.WriteFile(mf, []byte(bad), 0o644)
	out.Reset()
	if code := run([]string{"pin", "-m", mf, "--root", dir}, &out, &errb); code != 1 {
		t.Fatalf("missing required tool: exit %d\n%s", code, out.String())
	}
	if got, _ := os.ReadFile(mf); string(got) != bad {
		t.Errorf("failed pin modified the manifest:\n%s", got)
	}

	// A tool whose version cannot be extracted also fails.
	os.WriteFile(filepath.Join(dir, "bin", "hello"), []byte("#!/bin/sh\necho no version here\n"), 0o755)
	os.WriteFile(mf, []byte("[[tool]]\nname = \"hello\"\n"), 0o644)
	out.Reset()
	if code := run([]string{"pin", "-m", mf, "--root", dir}, &out, &errb); code != 1 || !strings.Contains(out.String(), "FAIL  hello") {
		t.Errorf("unparseable version: exit %d\n%s", code, out.String())
	}

	// A manifest with no tools is a usage error.
	os.WriteFile(mf, []byte("[exec_lint]\nwrappers = [\"oss-run\"]\n"), 0o644)
	if code := run([]string{"pin", "-m", mf}, &out, &errb); code != 2 {
		t.Errorf("no tools: exit %d", code)
	}
}

func TestPinRefusesWrongContext(t *testing.T) {
	other := "true"
	if check.DetectContainer() {
		other = "false"
	}
	doc := "require_container = " + other + "\n[[tool]]\nname = \"hello\"\n"
	dir, mf := pinFixture(t, doc)
	var out, errb bytes.Buffer
	if code := run([]string{"pin", "-m", mf, "--root", dir}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "requires running") {
		t.Fatalf("wrong context: exit %d\n%s", code, errb.String())
	}
	if code := run([]string{"pin", "-m", mf, "--root", dir, "--ignore-container"}, &out, &errb); code != 0 {
		t.Fatalf("--ignore-container: exit %d\n%s", code, errb.String())
	}
}

func TestPinThroughSymlink(t *testing.T) {
	dir, mf := pinFixture(t, "[[tool]]\nname = \"hello\"\n")
	link := filepath.Join(dir, "link.toml")
	if err := os.Symlink(mf, link); err != nil {
		t.Skip(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"pin", "-m", link, "--root", dir}, &out, &errb); code != 0 {
		t.Fatalf("pin via symlink: exit %d\n%s", code, errb.String())
	}
	if st, err := os.Lstat(link); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Error("symlink was replaced")
	}
	if got, _ := os.ReadFile(mf); !strings.Contains(string(got), "version = \"2.1.0\"") {
		t.Errorf("target not updated:\n%s", got)
	}
}
