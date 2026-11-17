package trace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sanilas-ai/toolchain-verify/internal/execpolicy"
)

func TestTraceJournal(t *testing.T) {
	if err := AllowJournal("auth.json"); err == nil {
		t.Fatal("auth.json was allowed")
	}
	span := "token-from-untrusted-page-xyz"
	journal := strings.Join([]string{
		`{"event":"result","name":"WebFetch","text":"` + span + `"}`,
		`{"event":"call","name":"Bash","args":"git status"}`,
		`{"event":"call","name":"Read","args":"/home/u/.ssh/id_rsa"}`,
		`{"event":"call","name":"send_email","args":"body ` + span + `"}`,
	}, "\n")
	pol := &execpolicy.Policy{Default: execpolicy.Host}
	rep := Scan(strings.NewReader(journal), Options{
		Policy: pol, Home: "/home/u", TrustedRoots: []string{"/work/repo"},
	})
	if rep.SchemaVersion != 1 || rep.OK {
		t.Fatalf("report: %+v", rep)
	}
	seen := map[string]int{}
	for _, f := range rep.Findings {
		seen[f.Rule]++
		if strings.Contains(f.Message, span) {
			t.Fatalf("finding copied the span: %s", f.Message)
		}
	}
	if seen["trace.shell"] != 0 {
		t.Fatalf("git status is allowed, got %+v", rep.Findings)
	}
	if seen["trace.path"] != 1 || seen["trace.flow"] != 1 {
		t.Fatalf("findings: %+v", rep.Findings)
	}

	outside := Scan(strings.NewReader(`{"event":"call","name":"Read","args":"/tmp/notes.txt"}`+"\n"), Options{
		Policy: pol, TrustedRoots: []string{"/work/repo"},
	})
	if outside.OK || outside.Findings[0].Rule != "trace.path" {
		t.Fatalf("outside root: %+v", outside.Findings)
	}
}

func TestTraceWatchKeepsTaint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.jsonl")
	span := "token-from-untrusted-page-xyz"
	if err := os.WriteFile(path, []byte(`{"event":"result","name":"WebFetch","text":"`+span+`"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pol := &execpolicy.Policy{Default: execpolicy.Host}
	stop := make(chan struct{})
	type result struct {
		rep *Report
		err error
	}
	done := make(chan result, 1)
	go func() {
		rep, err := Watch(path, Options{Policy: pol, StopOnFinding: true}, stop)
		done <- result{rep, err}
	}()
	time.Sleep(400 * time.Millisecond)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		close(stop)
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"event":"call","name":"send_email","args":"body ` + span + `"}` + "\n"); err != nil {
		f.Close()
		close(stop)
		t.Fatal(err)
	}
	f.Close()
	select {
	case got := <-done:
		if got.err != nil || got.rep == nil || got.rep.OK {
			t.Fatalf("watch: %+v %v", got.rep, got.err)
		}
	case <-time.After(3 * time.Second):
		close(stop)
		t.Fatal("watch did not connect the earlier result to the later call")
	}
}
