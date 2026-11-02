package findings

import "testing"

func TestCollector(t *testing.T) {
	c := Collector{Ignore: []string{"a.rule:/x/**", "b.rule"}}
	c.Add(Finding{Rule: "a.rule", Severity: SevWarn, Path: "/x/y/z"})
	c.Add(Finding{Rule: "a.rule", Severity: SevWarn, Path: "/q", Line: 3})
	c.Add(Finding{Rule: "a.rule", Severity: SevWarn, Path: "/q", Line: 3})
	c.Add(Finding{Rule: "b.rule", Severity: SevFail, Path: "/q"})
	c.Add(Finding{Rule: "c.rule", Severity: SevFail, Path: "/q"})
	got := c.Sorted()
	if len(got) != 2 || got[0].Rule != "c.rule" || got[1].Location() != "/q:3" || c.Ignored != 2 {
		t.Fatalf("got %+v ignored=%d", got, c.Ignored)
	}
	if OK(got, false) {
		t.Fatal("fail finding must not be OK")
	}
	if !OK(got[1:], false) || OK(got[1:], true) {
		t.Fatal("warn handling")
	}
}
