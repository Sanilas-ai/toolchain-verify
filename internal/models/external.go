package models

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// External scanners (picklescan, modelscan) are used when installed; they
// are never installed by this tool. They run with a minimal environment
// (PATH, HOME, LANG) so that API tokens in the caller's env are not passed on.

// Scanner results.
const (
	ScanClean       = "clean"
	ScanIssues      = "issues"
	ScanError       = "error"
	ScanUnsupported = "unsupported"
)

type scanner struct {
	name string // picklescan, modelscan or the configured base name
	path string
}

func (s scanner) handles(format string, pickle bool) bool {
	if s.name == "modelscan" {
		return pickle || format == FmtHDF5 || format == FmtKeras
	}
	return pickle
}

func (s scanner) args(file string) []string {
	switch s.name {
	case "picklescan":
		return []string{"--path", file}
	case "modelscan":
		return []string{"-p", file}
	}
	return []string{file}
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func (s scanner) run(file string, timeout time.Duration) (status, summary string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.path, s.args(file)...)
	home, _ := os.UserHomeDir()
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "LANG=C.UTF-8", "NO_COLOR=1"}
	cmd.Stdin = nil
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	text := strings.TrimSpace(ansiRe.ReplaceAllString(out.String(), ""))
	summary = tail(text, 400)
	if ctx.Err() != nil {
		return ScanError, "timed out after " + timeout.String()
	}
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return ScanError, err.Error()
		}
		code = ee.ExitCode()
	}
	switch {
	case code == 0:
		return ScanClean, summary
	case code == 1:
		return ScanIssues, summary
	case code == 3 && s.name == "modelscan":
		return ScanUnsupported, summary
	}
	return ScanError, summary
}

func tail(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return "…" + s[len(s)-n:]
	}
	return s
}

// findScanners resolves configured scanner names or paths.
func findScanners(names []string, lookPath func(string) (string, error)) []scanner {
	var out []scanner
	for _, n := range names {
		p := expandHome(n)
		var err error
		if !strings.ContainsRune(p, filepath.Separator) {
			p, err = lookPath(p)
		} else if _, err = os.Stat(p); err == nil {
			p, _ = filepath.Abs(p)
		}
		if err != nil {
			continue
		}
		out = append(out, scanner{name: filepath.Base(n), path: p})
	}
	return out
}
