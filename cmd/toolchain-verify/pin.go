package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Sanilas-ai/toolchain-verify/internal/agent"
	"github.com/Sanilas-ai/toolchain-verify/internal/check"
	"github.com/Sanilas-ai/toolchain-verify/internal/manifest"
)

// pinChange is one key that `pin` sets on one tool.
type pinChange struct {
	Tool, Key, Old, New string
}

func cmdPin(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pin", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("m", manifest.DefaultFile, "manifest file to update")
	fs.StringVar(path, "manifest", manifest.DefaultFile, "manifest file to update")
	root := fs.String("root", "", "look up tools in DIR/bin and DIR instead of PATH")
	timeout := fs.Duration("timeout", 10*time.Second, "timeout per version probe")
	mode := fs.String("version", "exact", "how to write version: exact (1.2.3), tilde (~1.2.3), caret (^1.2.3), min (>=1.2.3) or keep")
	noHash := fs.Bool("no-sha256", false, "do not write sha256")
	pinPath := fs.Bool("path", false, "also write the found binary path as `path`")
	var only multiFlag
	fs.Var(&only, "tool", "only pin this tool (repeatable; default all)")
	dryRun := fs.Bool("dry-run", false, "print what would change; do not write the manifest")
	ignoreCtx := fs.Bool("ignore-container", false, "pin even if require_container does not match where pin runs")
	allowUntrusted := fs.Bool("allow-untrusted-cwd", false, "allow auto-loading ./toolchain.toml from Downloads, /tmp, ...")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "error: unexpected arguments %v\n", fs.Args())
		return 2
	}
	verFmt, ok := map[string]string{"exact": "%s", "tilde": "~%s", "caret": "^%s", "min": ">=%s", "keep": ""}[*mode]
	if !ok {
		fmt.Fprintf(stderr, "error: --version must be exact, tilde, caret, min or keep (got %q)\n", *mode)
		return 2
	}
	if !flagSet(fs, "m", "manifest") && !*allowUntrusted && untrustedImplicitManifest(stderr) {
		return 2
	}

	// Write through a symlinked manifest instead of replacing the link.
	target, err := filepath.EvalSymlinks(*path)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	data, err := os.ReadFile(target)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	m, err := manifest.Parse(data)
	if err != nil {
		fmt.Fprintf(stderr, "error: %s: %v\n", *path, err)
		return 2
	}
	if len(m.Tools) == 0 {
		fmt.Fprintf(stderr, "error: %s has no [[tool]] entries to pin\n", *path)
		return 2
	}
	if m.RequireContainer != nil && !*ignoreCtx {
		if in := check.DetectContainer(); in != *m.RequireContainer {
			want := "inside a container (sandbox)"
			if !*m.RequireContainer {
				want = "on the host"
			}
			fmt.Fprintf(stderr, "error: %s requires running %s; pin there so the recorded versions and hashes match (or pass --ignore-container)\n", *path, want)
			return 2
		}
	}
	selected := map[string]bool{}
	for _, n := range only {
		selected[n] = false
	}
	for _, t := range m.Tools {
		if _, ok := selected[t.Name]; ok {
			selected[t.Name] = true
		}
	}
	var unknown []string
	for n, seen := range selected {
		if !seen {
			unknown = append(unknown, n)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		fmt.Fprintf(stderr, "error: --tool: no such tool in %s: %s\n", *path, strings.Join(unknown, ", "))
		return 2
	}

	var edits []manifest.ToolEdit
	var changes []pinChange
	failed := false
	fmt.Fprintf(stdout, "toolchain-verify pin: %s\n", *path)
	for i := range m.Tools {
		t := &m.Tools[i]
		if len(selected) > 0 && !selected[t.Name] {
			continue
		}
		o, err := check.Inspect(t, check.Options{Root: *root, Timeout: *timeout})
		if err != nil {
			var nf *check.NotFoundError
			if t.Optional && errors.As(err, &nf) {
				fmt.Fprintf(stdout, "  SKIP  %s: %v (optional, left unchanged)\n", t.Name, err)
				continue
			}
			fmt.Fprintf(stdout, "  FAIL  %s: %v\n", t.Name, err)
			failed = true
			continue
		}
		set := map[string]string{}
		add := func(key, old, val string) {
			if old != val {
				set[key] = val
				changes = append(changes, pinChange{t.Name, key, old, val})
			}
		}
		if verFmt != "" {
			add("version", t.Version, fmt.Sprintf(verFmt, o.Version))
		}
		if *pinPath {
			if strings.ContainsAny(o.Found, "*?") {
				fmt.Fprintf(stdout, "  WARN  %s: path %s contains glob characters; path not pinned\n", t.Name, o.Found)
			} else {
				add("path", t.Path, o.Found)
			}
		}
		if !*noHash {
			add("sha256", t.SHA256, o.SHA256)
		}
		status := "OK  "
		if len(set) > 0 {
			status = "PIN "
			edits = append(edits, manifest.ToolEdit{Index: i, Set: set})
		}
		fmt.Fprintf(stdout, "  %s  %s %s (%s)\n", status, t.Name, o.Version, o.Resolved)
	}
	for _, c := range changes {
		old := c.Old
		if old == "" {
			old = "(unset)"
		}
		fmt.Fprintf(stdout, "        %s.%s: %s -> %s\n", c.Tool, c.Key, old, c.New)
	}
	if failed {
		fmt.Fprintf(stdout, "FAIL: some tools could not be inspected; %s not modified\n", *path)
		return 1
	}
	if len(changes) == 0 {
		fmt.Fprintf(stdout, "up to date: %s already matches this environment\n", *path)
		return 0
	}
	out, err := manifest.EditTools(data, edits)
	if err != nil {
		fmt.Fprintf(stderr, "error: %s: %v\n", *path, err)
		return 2
	}
	if _, err := manifest.Parse(out); err != nil {
		fmt.Fprintf(stderr, "error: pinned manifest would not load: %v\n", err)
		return 2
	}
	if *dryRun {
		fmt.Fprintf(stdout, "dry run: %d change(s), %s not modified\n", len(changes), *path)
		return 0
	}
	if err := writeFileAtomic(target, out); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	fmt.Fprintf(stdout, "wrote %s (%d change(s))\n", *path, len(changes))
	return 0
}

// untrustedImplicitManifest reports (and explains on stderr) whether the
// implicit ./toolchain.toml would come from an untrusted directory such as
// Downloads or /tmp. Commands that execute the tools a manifest names must
// never pick such a file up implicitly.
func untrustedImplicitManifest(stderr io.Writer) bool {
	cwd, err := os.Getwd()
	if err != nil {
		return false
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	if d, bad := agent.UntrustedCwd(cwd, home, nil); bad {
		fmt.Fprintf(stderr, "error: refusing to load ./%s from untrusted directory %s (it would run the commands it names); pass -m explicitly or --allow-untrusted-cwd\n", manifest.DefaultFile, d)
		return true
	}
	return false
}

// writeFileAtomic replaces path with data via a temp file in the same
// directory, keeping the original permissions.
func writeFileAtomic(path string, data []byte) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".pin-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(st.Mode().Perm()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
