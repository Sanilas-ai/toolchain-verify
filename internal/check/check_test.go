package check

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Sanilas-ai/toolchain-verify/internal/manifest"
)

func TestGlobToRegexp(t *testing.T) {
	tests := []struct {
		glob, path string
		want       bool
	}{
		{"/usr/bin/git", "/usr/bin/git", true},
		{"/usr/bin/python3*", "/usr/bin/python3.10", true},
		{"/usr/bin/*", "/usr/bin/sub/git", false},
		{"/opt/node/**", "/opt/node/bin/node", true},
		{"/opt/**/bin/go", "/opt/go/1.22/bin/go", true},
		{"/usr/bin/g?t", "/usr/bin/git", true},
		{"/usr/bin/g.t", "/usr/bin/git", false},
	}
	for _, tc := range tests {
		re, err := globToRegexp(tc.glob)
		if err != nil {
			t.Fatal(err)
		}
		if got := re.MatchString(tc.path); got != tc.want {
			t.Errorf("glob %q vs %q = %v, want %v", tc.glob, tc.path, got, tc.want)
		}
	}
}

func writeTool(t *testing.T, dir, name, output string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	script := "#!/bin/sh\necho '" + output + "'\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(script))
	return hex.EncodeToString(sum[:])
}

func TestRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts")
	}
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := writeTool(t, bin, "faketool", "faketool version 1.4.2 (linux)")
	writeTool(t, bin, "oldtool", "oldtool 0.9.0")
	if err := os.Symlink(filepath.Join(bin, "faketool"), filepath.Join(bin, "alias")); err != nil {
		t.Fatal(err)
	}

	no := false
	m, err := manifest.Parse([]byte(`
[[tool]]
name = "faketool"
version = "^1.4"
path = "bin/faketool"
sha256 = "` + sum + `"

[[tool]]
name = "alias"
version = "1.4.2"
version_regex = 'version (?P<version>[0-9.]+)'
path = "**/faketool"

[[tool]]
name = "oldtool"
version = ">=1.0"

[[tool]]
name = "badhash"
command = "faketool"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"

[[tool]]
name = "wrongpath"
command = "faketool"
path = "/usr/local/bin/faketool"

[[tool]]
name = "missing"

[[tool]]
name = "maybe"
optional = true
`))
	if err != nil {
		t.Fatal(err)
	}
	rep := Run(m, "test.toml", Options{Root: root, InContainer: &no})
	if rep.OK {
		t.Error("report should fail")
	}
	want := map[string]string{
		"faketool":  StatusOK,
		"alias":     StatusOK,
		"oldtool":   StatusFail,
		"badhash":   StatusFail,
		"wrongpath": StatusFail,
		"missing":   StatusFail,
		"maybe":     StatusSkip,
	}
	for _, r := range rep.Tools {
		if r.Status != want[r.Name] {
			t.Errorf("%s: status %s, want %s (problems: %v)", r.Name, r.Status, want[r.Name], r.Problems)
		}
	}
	if r := rep.Tools[0]; r.Version != "1.4.2" || r.SHA256 != sum {
		t.Errorf("faketool result: %+v", r)
	}
	if r := rep.Tools[1]; !strings.HasSuffix(r.Resolved, "/faketool") {
		t.Errorf("alias should resolve to faketool, got %s", r.Resolved)
	}
	if ok, fail, skip := rep.Counts(); ok != 2 || fail != 4 || skip != 1 {
		t.Errorf("counts = %d/%d/%d", ok, fail, skip)
	}
}

func TestRequireContainer(t *testing.T) {
	root := t.TempDir()
	writeTool(t, root, "x", "x 1.0.0")
	yes, no := true, false
	m, err := manifest.Parse([]byte("require_container = true\n[[tool]]\nname = \"x\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if rep := Run(m, "t", Options{Root: root, InContainer: &no}); rep.OK || len(rep.Problems) != 1 {
		t.Errorf("host run should fail: %+v", rep)
	}
	if rep := Run(m, "t", Options{Root: root, InContainer: &yes}); !rep.OK {
		t.Errorf("container run should pass: %+v", rep)
	}
}

func TestLocateSkipsRelativePathEntries(t *testing.T) {
	dir := t.TempDir()
	writeTool(t, dir, "planted", "planted 1.0.0")
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := locate("planted", Options{PathEnv: ".:" + string(os.PathListSeparator)}); err == nil {
		t.Error("relative PATH entry must not be searched")
	}
	if p, err := locate("planted", Options{PathEnv: dir}); err != nil || p != filepath.Join(dir, "planted") {
		t.Errorf("absolute PATH entry: %s %v", p, err)
	}
}

func TestRelativePathGlobErrorMentionsManifestDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts")
	}
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	os.Mkdir(bin, 0o755)
	writeTool(t, bin, "faketool", "faketool version 1.0.0")
	mfDir := filepath.Join(root, "manifests")
	os.Mkdir(mfDir, 0o755)
	no := false
	m, err := manifest.Parse([]byte(`
[[tool]]
name = "faketool"
version = ">=1.0"
path = "wrong/bin/faketool"
`))
	if err != nil {
		t.Fatal(err)
	}
	m.Dir = mfDir
	rep := Run(m, filepath.Join(mfDir, "toolchain.toml"), Options{Root: root, InContainer: &no})
	if rep.OK {
		t.Fatal("expected fail")
	}
	var problems []string
	for _, tr := range rep.Tools {
		if tr.Name == "faketool" {
			problems = tr.Problems
		}
	}
	joined := strings.Join(problems, "; ")
	if !strings.Contains(joined, "relative path globs resolve against") {
		t.Fatalf("missing relative-glob hint: %s", joined)
	}
	// With Options.Root set, relative globs resolve against --root (documented).
	if !strings.Contains(joined, root) {
		t.Fatalf("missing resolved base %s in: %s", root, joined)
	}
	if !strings.Contains(joined, "resolved pattern:") {
		t.Fatalf("missing resolved pattern: %s", joined)
	}
}

func TestRelativePathGlobAgainstManifestDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts")
	}
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	os.Mkdir(bin, 0o755)
	writeTool(t, bin, "faketool", "faketool version 1.0.0")
	// Put the binary on PATH and leave Options.Root empty so relative globs
	// resolve against the manifest directory.
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", bin+string(os.PathListSeparator)+oldPath)
	defer os.Setenv("PATH", oldPath)
	mfDir := filepath.Join(root, "manifests")
	os.Mkdir(mfDir, 0o755)
	no := false
	m, err := manifest.Parse([]byte(`
[[tool]]
name = "faketool"
version = ">=1.0"
path = "wrong/bin/faketool"
`))
	if err != nil {
		t.Fatal(err)
	}
	m.Dir = mfDir
	rep := Run(m, filepath.Join(mfDir, "toolchain.toml"), Options{InContainer: &no})
	var problems []string
	for _, tr := range rep.Tools {
		if tr.Name == "faketool" {
			problems = tr.Problems
		}
	}
	joined := strings.Join(problems, "; ")
	if !strings.Contains(joined, "manifest directory") || !strings.Contains(joined, mfDir) {
		t.Fatalf("expected manifest-dir hint, got: %s", joined)
	}
}
