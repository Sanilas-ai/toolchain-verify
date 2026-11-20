package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/Sanilas-ai/toolchain-verify/internal/execpolicy"
	"github.com/Sanilas-ai/toolchain-verify/internal/manifest"
	"github.com/Sanilas-ai/toolchain-verify/internal/trace"
)

func cmdTrace(args []string, stdout, stderr io.Writer) int {
	watch := false
	if len(args) > 0 && args[0] == "watch" {
		watch = true
		args = args[1:]
	}
	fs := flag.NewFlagSet("trace", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("m", "", "exec policy file (a manifest with [exec_policy])")
	asJSON := fs.Bool("json", false, "print a JSON report")
	follow := fs.Bool("follow-script", false, "judge one script file named by a shell tool call")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: toolchain-verify trace [watch] [-m policy.toml] [--json] JOURNAL")
		return 2
	}
	journal := fs.Arg(0)
	if err := trace.AllowJournal(journal); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	var pol *execpolicy.Policy
	if *path != "" {
		m, err := manifest.Load(*path)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		if m.ExecPolicy == nil {
			fmt.Fprintf(stderr, "error: %s: no [exec_policy] section\n", *path)
			return 2
		}
		pol = m.ExecPolicy
	}
	cwd, home := cwdHome()
	opt := trace.Options{Policy: pol, Home: home, Cwd: cwd, FollowScript: *follow, StopOnFinding: watch}
	var rep *trace.Report
	var err error
	if watch {
		stop := make(chan struct{})
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		go func() {
			<-sig
			close(stop)
		}()
		done := make(chan struct{})
		go func() {
			rep, err = trace.Watch(journal, opt, stop)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(24 * time.Hour):
			close(stop)
			<-done
		}
	} else {
		f, e := os.Open(journal)
		if e != nil {
			fmt.Fprintln(stderr, "error:", e)
			return 2
		}
		defer f.Close()
		rep = trace.Scan(f, opt)
		rep.Path = journal
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if *asJSON {
		writeJSON(stdout, rep)
	} else {
		fmt.Fprintf(stdout, "toolchain-verify trace: %s (%d events)\n", rep.Path, rep.Events)
		for _, f := range rep.Findings {
			fmt.Fprintf(stdout, "  %-4s  %-16s %s\n        %s\n", f.Severity, f.Rule, f.Path, f.Message)
		}
		if rep.OK {
			fmt.Fprintln(stdout, "PASS")
		} else {
			fmt.Fprintln(stdout, "FAIL")
		}
	}
	if rep.OK {
		return 0
	}
	return 1
}
