package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Sanilas-ai/toolchain-verify/internal/agent"
	"github.com/Sanilas-ai/toolchain-verify/internal/dockerhost"
	"github.com/Sanilas-ai/toolchain-verify/internal/execlint"
	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
	"github.com/Sanilas-ai/toolchain-verify/internal/manifest"
)

// policyManifest loads -m, or ./toolchain.toml when cwd is not an
// untrusted location (a planted manifest could weaken the policy).
// It returns nil when there is nothing to load.
func policyManifest(fs *flag.FlagSet, path, cwd, home string, stderr io.Writer) (*manifest.Manifest, error) {
	explicit := flagSet(fs, "m", "manifest")
	if !explicit {
		path = filepath.Join(cwd, manifest.DefaultFile)
		if _, err := os.Stat(path); err != nil {
			return nil, nil
		}
		if d, bad := agent.UntrustedCwd(cwd, home, nil); bad {
			fmt.Fprintf(stderr, "warning: not loading %s from untrusted directory %s (a planted manifest could weaken the policy); using defaults\n", path, d)
			return nil, nil
		}
	}
	return manifest.Load(path)
}

func cwdHome() (string, string) {
	cwd, _ := os.Getwd()
	cwd, _ = filepath.Abs(cwd)
	home, _ := os.UserHomeDir()
	return cwd, home
}

func writeJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func printFindings(w io.Writer, fs []findings.Finding, verbose bool) {
	for _, f := range fs {
		if f.Severity == findings.SevInfo && !verbose {
			continue
		}
		fmt.Fprintf(w, "  %-4s  %-22s %s\n", strings.ToUpper(f.Severity), f.Rule, orDash(f.Location()))
		fmt.Fprintf(w, "        %s\n", f.Message)
		if f.Fix != "" && (verbose || f.Severity == findings.SevFail) {
			fmt.Fprintf(w, "        fix: %s\n", f.Fix)
		}
	}
}

func verdict(w io.Writer, fs []findings.Finding, ok, strict bool, ignored int) {
	fail, warn, info := findings.Counts(fs)
	v := "PASS"
	if !ok {
		v = "FAIL"
	}
	extra := ""
	if ignored > 0 {
		extra = fmt.Sprintf(", %d ignored", ignored)
	}
	if strict {
		extra += " (strict)"
	}
	fmt.Fprintf(w, "%s: %d failed, %d warnings, %d info%s\n", v, fail, warn, info, extra)
}

func cmdExecLint(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("exec-lint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("m", manifest.DefaultFile, "manifest with an [exec_lint] section (optional)")
	fs.StringVar(path, "manifest", manifest.DefaultFile, "manifest with an [exec_lint] section (optional)")
	fail := fs.Bool("fail", false, "findings fail the run (CI gate; same as exec_lint.mode = \"fail\")")
	strict := fs.Bool("strict", false, "warnings fail the run")
	includeTests := fs.Bool("include-tests", false, "also lint test files")
	var wrappers multiFlag
	fs.Var(&wrappers, "wrapper", "extra approved sandbox wrapper name (repeatable)")
	asJSON := fs.Bool("json", false, "print a JSON report")
	verbose := fs.Bool("v", false, "verbose: also print info findings (wrapped/annotated calls) and fixes")
	quiet := fs.Bool("q", false, "print nothing when the run passes")
	fs.BoolVar(quiet, "quiet", false, "print nothing when the run passes")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cwd, home := cwdHome()
	m, err := policyManifest(fs, *path, cwd, home, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	var pol *execlint.Policy
	opt := execlint.Options{Home: home, Cwd: cwd, Paths: fs.Args(), Fail: *fail, Strict: *strict, ExtraWrappers: wrappers}
	if m != nil {
		pol, opt.ManifestDir = m.ExecLint, m.Dir
	}
	if *includeTests {
		if pol == nil {
			pol = &execlint.Policy{}
		}
		cp := *pol
		cp.IncludeTests = true
		pol = &cp
	}
	rep, err := execlint.Run(pol, opt)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if *asJSON {
		writeJSON(stdout, rep)
	} else if !(*quiet && rep.OK) {
		fmt.Fprintf(stdout, "toolchain-verify exec-lint: %s (mode %s; %d files, %d with LLM context, %d exec sinks)\n",
			strings.Join(rep.Roots, ", "), rep.Mode, rep.Files, rep.LLMFiles, rep.Sinks)
		if rep.Truncated {
			fmt.Fprintln(stdout, "  note: file limit reached; results are partial")
		}
		printFindings(stdout, rep.Findings, *verbose)
		verdict(stdout, rep.Findings, rep.OK, rep.Strict, rep.Ignored)
	}
	if !rep.OK {
		return 1
	}
	return 0
}

func cmdDocker(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("docker", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("m", manifest.DefaultFile, "manifest with a [docker] section (optional)")
	fs.StringVar(path, "manifest", manifest.DefaultFile, "manifest with a [docker] section (optional)")
	socket := fs.String("socket", "", "engine unix socket (absolute path) or \"off\"")
	requireEngine := fs.Bool("require-engine", false, "fail when no engine can be queried")
	strict := fs.Bool("strict", false, "warnings fail the run")
	asJSON := fs.Bool("json", false, "print a JSON report")
	verbose := fs.Bool("v", false, "verbose: also print info findings and fixes")
	quiet := fs.Bool("q", false, "print nothing when the run passes")
	fs.BoolVar(quiet, "quiet", false, "print nothing when the run passes")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "error: unexpected arguments %v\n", fs.Args())
		return 2
	}
	cwd, home := cwdHome()
	m, err := policyManifest(fs, *path, cwd, home, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	pol := &dockerhost.Policy{}
	if m != nil && m.Docker != nil {
		cp := *m.Docker
		pol = &cp
	}
	if *requireEngine {
		pol.RequireEngine = true
	}
	rep, err := dockerhost.Run(pol, dockerhost.Options{Home: home, Socket: *socket, Strict: *strict})
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if *asJSON {
		writeJSON(stdout, rep)
	} else if !(*quiet && rep.OK) {
		eng := "no engine queried"
		if rep.Engine != nil {
			eng = fmt.Sprintf("engine %s via %s", orDash(rep.Engine.Version), rep.Engine.Socket)
			if rep.Engine.Rootless {
				eng += " (rootless)"
			}
		}
		fmt.Fprintf(stdout, "toolchain-verify docker: %s; %d containers (%d running)\n", eng, rep.Containers, rep.Running)
		printFindings(stdout, rep.Findings, *verbose)
		verdict(stdout, rep.Findings, rep.OK, rep.Strict, rep.Ignored)
	}
	if !rep.OK {
		return 1
	}
	return 0
}
