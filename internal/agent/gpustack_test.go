package agent

import (
	"testing"

	"github.com/Sanilas-ai/toolchain-verify/internal/version"
)

// GPUStack: CVE-2026-102895 (KEV) + CVE-2026-102894; 2.2.2 is the floor.
func TestBuiltinGPUStackFloor(t *testing.T) {
	db, err := LoadDB(true, nil)
	if err != nil {
		t.Fatal(err)
	}
	i := db.stackIndex("gpustack")
	if i < 0 {
		t.Fatal("gpustack stack missing")
	}
	st := &db.Stacks[i]
	for _, c := range []struct {
		v    string
		want int
	}{{"0.6.0", 1}, {"2.1.1", 2}, {"2.2.0", 1}, {"2.2.1", 1}, {"2.2.2", 0}, {"2.3.1", 0}} {
		v, err := version.Parse(c.v)
		if err != nil {
			t.Fatal(err)
		}
		got := db.advisoriesFor(st, "gpustack", v)
		if len(got) != c.want {
			t.Errorf("gpustack %s: %d advisories, want %d", c.v, len(got), c.want)
		}
		for _, a := range got {
			if a.Severity != "critical" {
				t.Errorf("%s: severity %s", a.ID, a.Severity)
			}
		}
	}
}
