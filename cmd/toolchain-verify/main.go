// Command toolchain-verify checks installed development tools against a
// declarative manifest (toolchain.toml).
package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Sanilas-ai/toolchain-verify/internal/check"
	"github.com/Sanilas-ai/toolchain-verify/internal/manifest"
)

//go:embed sample.toml
var sample string

var buildVersion = "dev"

const usage = `toolchain-verify — verify a development toolchain against a manifest

Usage:
  toolchain-verify check [-m toolchain.toml] [--root DIR] [--json] [-v] [--timeout 10s]
  toolchain-verify init  [-m toolchain.toml] [--force]
  toolchain-verify version

Exit codes: 0 all checks passed, 1 a check failed, 2 usage or manifest error.
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "check":
		return cmdCheck(args[1:], stdout, stderr)
	case "init":
		return cmdInit(args[1:], stdout, stderr)
	case "version", "--version":
		fmt.Fprintln(stdout, "toolchain-verify", buildVersion)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return 2
}

func cmdCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("m", manifest.DefaultFile, "manifest file")
	fs.StringVar(path, "manifest", manifest.DefaultFile, "manifest file")
	root := fs.String("root", "", "look up tools in DIR/bin and DIR instead of PATH")
	asJSON := fs.Bool("json", false, "print a JSON report")
	verbose := fs.Bool("v", false, "verbose: print resolved paths and SHA-256 digests")
	timeout := fs.Duration("timeout", 10*time.Second, "timeout per version probe")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	m, err := manifest.Load(*path)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	rep := check.Run(m, *path, check.Options{Root: *root, Timeout: *timeout})
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		_ = enc.Encode(rep)
	} else {
		printHuman(stdout, rep, *verbose)
	}
	if !rep.OK {
		return 1
	}
	return 0
}

func printHuman(w io.Writer, rep *check.Report, verbose bool) {
	ctx := "host"
	if rep.InContainer {
		ctx = "container"
	}
	fmt.Fprintf(w, "toolchain-verify: %s (running in %s)\n", rep.Manifest, ctx)
	for _, p := range rep.Problems {
		fmt.Fprintf(w, "  FAIL  environment: %s\n", p)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, t := range rep.Tools {
		ver := t.Version
		if ver == "" {
			ver = "-"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", strings.ToUpper(t.Status), t.Name, ver, orDash(t.Constraint), orDash(t.Found))
		if verbose && t.Resolved != "" {
			fmt.Fprintf(tw, "  \t\t\t\tresolved: %s\n", t.Resolved)
			fmt.Fprintf(tw, "  \t\t\t\tsha256:   %s\n", t.SHA256)
		}
		for _, p := range t.Problems {
			fmt.Fprintf(tw, "  \t\t\t\t- %s\n", p)
		}
	}
	tw.Flush()
	ok, fail, skip := rep.Counts()
	verdict := "PASS"
	if !rep.OK {
		verdict = "FAIL"
	}
	fmt.Fprintf(w, "%s: %d ok, %d failed, %d skipped\n", verdict, ok, fail, skip)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func cmdInit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("m", manifest.DefaultFile, "manifest file to write")
	fs.StringVar(path, "manifest", manifest.DefaultFile, "manifest file to write")
	force := fs.Bool("force", false, "overwrite an existing file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if *force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(*path, flags, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			fmt.Fprintf(stderr, "error: %s already exists (use --force to overwrite)\n", *path)
		} else {
			fmt.Fprintln(stderr, "error:", err)
		}
		return 2
	}
	defer f.Close()
	if _, err := f.WriteString(sample); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	fmt.Fprintf(stdout, "wrote %s\n", *path)
	return 0
}
