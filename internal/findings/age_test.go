package findings

import (
	"testing"
	"time"
)

func TestStaleDatabase(t *testing.T) {
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	if _, ok := StaleDatabase("advisories.toml", "2026-11-02", now, 45); ok {
		t.Fatal("14 days is inside 45")
	}
	if _, ok := StaleDatabase("advisories.toml", "", now, 45); !ok {
		t.Fatal("empty date is unparseable")
	}
	f, ok := StaleDatabase("advisories.toml", "2020-01-01", now, 0)
	if !ok || f.Rule != "policy.db-stale" || f.Severity != SevWarn {
		t.Fatalf("%+v %v", f, ok)
	}
	if _, ok := StaleDatabase("advisories.toml", "2020-01-01", now, -1); ok {
		t.Fatal("negative max age disables the check")
	}
}
