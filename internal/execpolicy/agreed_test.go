package execpolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnexpandedArgv0(t *testing.T) {
	p := loadPolicy(t)
	for _, cmd := range []string{"$CMD status", "${CMD} status", "sudo $CMD status", "env -i $BIN status"} {
		d := check(p, cmd)
		if d.Verdict != Deny || !strings.Contains(d.Reason, "unexpanded") {
			t.Errorf("%q: verdict %s reason %q", cmd, d.Verdict, d.Reason)
		}
	}
	if d := check(p, "echo $HOME"); strings.Contains(d.Reason, "unexpanded") {
		t.Errorf("a variable in an argument is not argv[0]: %+v", d)
	}
}

func TestFollowScript(t *testing.T) {
	p := loadPolicy(t)
	dir := t.TempDir()
	script := filepath.Join(dir, "run.sh")
	if err := os.WriteFile(script, []byte("go test ./...\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := Check(p, Input{Command: "bash run.sh", Cwd: dir, Home: "/home/u", InSandbox: &no, FollowScript: true})
	if d.Verdict != Sandbox {
		t.Fatalf("script inside cwd: %+v", d)
	}
	missing := Check(p, Input{Command: "bash missing.sh", Cwd: dir, Home: "/home/u", InSandbox: &no, FollowScript: true})
	if missing.Verdict != Host {
		t.Fatalf("missing script must not be followed: %+v", missing)
	}
	outside := Check(p, Input{Command: "bash /tmp/other.sh", Cwd: dir, Home: "/home/u", InSandbox: &no, FollowScript: true})
	if outside.Verdict != Host {
		t.Fatalf("script outside cwd must not be followed: %+v", outside)
	}
}
