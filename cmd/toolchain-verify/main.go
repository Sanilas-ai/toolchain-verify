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
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Sanilas-ai/toolchain-verify/internal/agent"
	"github.com/Sanilas-ai/toolchain-verify/internal/check"
	"github.com/Sanilas-ai/toolchain-verify/internal/manifest"
)

//go:embed sample.toml
var sample string

var buildVersion = "dev"

const usage = `toolchain-verify — verify a development toolchain against a manifest

Usage:
  toolchain-verify check [-m toolchain.toml] [--root DIR] [--json] [-v] [--timeout 10s]
  toolchain-verify agent [-m toolchain.toml] [--trusted DIR]... [--advisories FILE]...
                         [--strict] [--json] [-v] [-q] [--list-advisories]
                         [--pre-session] [--allow-untrusted-cwd]
                         [--quarantine [--quarantine-dir DIR]] [--no-host-inventory]
  toolchain-verify exec-lint [-m toolchain.toml] [--fail] [--strict] [--wrapper NAME]...
                         [--include-tests] [--json] [-v] [-q] [PATH...]
  toolchain-verify docker [-m toolchain.toml] [--socket PATH|off] [--require-engine]
                         [--strict] [--json] [-v] [-q]
  toolchain-verify init  [-m toolchain.toml] [--force]
  toolchain-verify version

  check  verify tool versions/paths/hashes (runs each tool's version probe)
  agent  read-only agent-protection audit: planted AGENTS.md/CLAUDE.md/rules
         files, vulnerable agent stacks (Flowise, Langflow, PraisonAI, ...),
         MCP/approval settings, credential permissions, package-index setup.
         Never executes binaries and never opens credential files.
         --pre-session   fast gate before starting an agent: only the cwd
         --quarantine    move planted instruction/MCP files out of untrusted
                         dirs (the only option that changes anything)
  exec-lint  find subprocess/exec/eval calls in files that handle LLM output
         that do not go through a hardened container (docker run --network
         none --read-only --cap-drop ALL --user nobody). Report mode by
         default; --fail turns findings into a CI gate.
  docker read-only Docker/Podman host hygiene: ports on 0.0.0.0, privileged
         containers, socket/host mounts, :latest images, docker group,
         dockerd on TCP, unneeded egress. Engine API is queried with GET only.

Exit codes: 0 all checks passed, 1 a check failed, 2 usage, manifest or
refused-configuration error, 3 agent refused an untrusted working directory
(--pre-session).
`

// exitUntrustedCwd is returned by `agent --pre-session` when the working
// directory is an untrusted location (Downloads, /tmp, ...).
const exitUntrustedCwd = 3

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
	case "agent", "protect":
		return cmdAgent(args[1:], stdout, stderr)
	case "exec-lint":
		return cmdExecLint(args[1:], stdout, stderr)
	case "docker", "docker-hygiene":
		return cmdDocker(args[1:], stdout, stderr)
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
	allowUntrusted := fs.Bool("allow-untrusted-cwd", false, "allow auto-loading ./toolchain.toml from Downloads, /tmp, ...")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !flagSet(fs, "m", "manifest") && !*allowUntrusted {
		// `check` executes the commands named in the manifest. A toolchain.toml
		// planted in Downloads or /tmp must never be picked up implicitly.
		if cwd, err := os.Getwd(); err == nil {
			if home, err := os.UserHomeDir(); err == nil {
				if d, bad := agent.UntrustedCwd(cwd, home, nil); bad {
					fmt.Fprintf(stderr, "error: refusing to load ./%s from untrusted directory %s (it would run the commands it names); pass -m explicitly or --allow-untrusted-cwd\n", manifest.DefaultFile, d)
					return 2
				}
			}
		}
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

func flagSet(fs *flag.FlagSet, names ...string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		for _, n := range names {
			if f.Name == n {
				set = true
			}
		}
	})
	return set
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func cmdAgent(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("m", manifest.DefaultFile, "manifest with an [agent] section (optional)")
	fs.StringVar(path, "manifest", manifest.DefaultFile, "manifest with an [agent] section (optional)")
	var trusted, advisories multiFlag
	fs.Var(&trusted, "trusted", "trusted project root (repeatable; adds to agent.trusted_roots)")
	fs.Var(&advisories, "advisories", "extra advisory database TOML (repeatable)")
	noBuiltin := fs.Bool("no-builtin-advisories", false, "do not load the embedded advisory database")
	strict := fs.Bool("strict", false, "warnings fail the run")
	asJSON := fs.Bool("json", false, "print a JSON report")
	verbose := fs.Bool("v", false, "verbose: also print info findings and fixes")
	list := fs.Bool("list-advisories", false, "print the advisory database and exit")
	home := fs.String("home", "", "home directory to audit (default: current user's)")
	cwdFlag := fs.String("cwd", "", "working directory to evaluate (default: current)")
	preSession := fs.Bool("pre-session", false, "only check the working directory; exit 3 if it is untrusted (run before starting an agent)")
	allowCwd := fs.Bool("allow-untrusted-cwd", false, "downgrade cwd.untrusted to a warning (and let --pre-session pass)")
	quarantine := fs.Bool("quarantine", false, "move planted instruction/MCP files found in untrusted dirs into the quarantine dir")
	quarantineDir := fs.String("quarantine-dir", "", "quarantine destination (default agent.quarantine_dir or ~/.local/state/toolchain-verify/quarantine)")
	noHost := fs.Bool("no-host-inventory", false, "skip snap, systemd and Docker/Podman engine inventory")
	quiet := fs.Bool("q", false, "quiet: print nothing when the run passes (cron)")
	fs.BoolVar(quiet, "quiet", false, "quiet: print nothing when the run passes (cron)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *quarantineDir != "" && !*quarantine {
		fmt.Fprintln(stderr, "error: --quarantine-dir needs --quarantine")
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "error: unexpected arguments %v\n", fs.Args())
		return 2
	}
	if *list {
		db, err := agent.LoadDB(!*noBuiltin, advisories)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		printAdvisories(stdout, db, *asJSON)
		return 0
	}
	cwd := *cwdFlag
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	cwd, _ = filepath.Abs(cwd)
	h := *home
	if h == "" {
		h, _ = os.UserHomeDir()
	}

	var pol *agent.Policy
	opt := agent.Options{Home: h, Cwd: cwd, InContainer: check.DetectContainer(), ExtraTrusted: trusted,
		ExtraAdvisories: advisories, NoBuiltinAdvisories: *noBuiltin, Strict: *strict,
		AllowUntrustedCwd: *allowCwd, Quarantine: *quarantine, QuarantineDir: *quarantineDir, NoHostInventory: *noHost}
	explicit := flagSet(fs, "m", "manifest")
	mpath := *path
	if !explicit {
		mpath = filepath.Join(cwd, manifest.DefaultFile)
	}
	load := explicit
	if !explicit {
		if _, err := os.Stat(mpath); err == nil {
			if d, bad := agent.UntrustedCwd(cwd, h, trusted); bad {
				fmt.Fprintf(stderr, "warning: not loading %s from untrusted directory %s (a planted manifest could weaken the policy); using defaults\n", mpath, d)
			} else {
				load = true
			}
		}
	}
	if load {
		m, err := manifest.Load(mpath)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		pol = m.Agent
		opt.RequireContainer = m.RequireContainer
		opt.ManifestDir = m.Dir
	}
	var rep *agent.Report
	var err error
	if *preSession {
		rep, err = agent.RunPreSession(pol, opt)
	} else {
		rep, err = agent.Run(pol, opt)
	}
	if err != nil && !errors.Is(err, agent.ErrUntrustedCwd) {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if !(*quiet && rep.OK && err == nil) {
		if *asJSON {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			enc.SetEscapeHTML(false)
			_ = enc.Encode(rep)
		} else {
			printAgent(stdout, rep, *verbose)
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "refused: %s is an untrusted working directory; do not start a coding agent here (cd into a trusted project, or pass --allow-untrusted-cwd)\n", rep.Cwd)
		return exitUntrustedCwd
	}
	if !rep.OK {
		return 1
	}
	return 0
}

func printAgent(w io.Writer, rep *agent.Report, verbose bool) {
	ctx := "host"
	if rep.InContainer {
		ctx = "container"
	}
	if rep.PreSession {
		fmt.Fprintf(w, "toolchain-verify agent --pre-session: cwd %s (running in %s)\n", rep.Cwd, ctx)
	} else {
		fmt.Fprintf(w, "toolchain-verify agent: cwd %s (running in %s; advisories updated %s)\n", rep.Cwd, ctx, rep.AdvisoryDB)
	}
	if len(rep.TrustedRoots) == 0 {
		fmt.Fprintln(w, "  note: no trusted roots configured (agent.trusted_roots / --trusted)")
	} else if verbose {
		fmt.Fprintf(w, "  trusted roots: %s\n", strings.Join(rep.TrustedRoots, ", "))
	}
	for _, f := range rep.Findings {
		if f.Severity == agent.SevInfo && !verbose {
			continue
		}
		fmt.Fprintf(w, "  %-4s  %-26s %s\n", strings.ToUpper(f.Severity), f.Rule, orDash(f.Path))
		fmt.Fprintf(w, "        %s\n", f.Message)
		if f.Fix != "" && (verbose || f.Severity == agent.SevFail) {
			fmt.Fprintf(w, "        fix: %s\n", f.Fix)
		}
		if verbose {
			for _, r := range f.Refs {
				fmt.Fprintf(w, "        ref: %s\n", r)
			}
		}
	}
	if verbose && len(rep.Installs) > 0 {
		fmt.Fprintln(w, "  agent stacks found:")
		for _, in := range rep.Installs {
			v := ""
			if len(in.Vulnerable) > 0 {
				v = " [" + strings.Join(in.Vulnerable, ", ") + "]"
			}
			fmt.Fprintf(w, "    %s %s %s (%s) %s%s\n", in.Stack, in.Package, in.Version, in.Source, in.Path, v)
		}
	}
	if len(rep.Quarantined) > 0 {
		fmt.Fprintf(w, "  quarantine: %s\n", rep.QuarantineDir)
		for _, q := range rep.Quarantined {
			if q.Error != "" {
				fmt.Fprintf(w, "    FAILED  %s: %s\n", q.From, q.Error)
			} else {
				fmt.Fprintf(w, "    moved   %s -> %s\n", q.From, q.To)
			}
		}
	}
	fail, warn, info := rep.Counts()
	verdict := "PASS"
	if !rep.OK {
		verdict = "FAIL"
	}
	extra := ""
	if rep.Ignored > 0 {
		extra = fmt.Sprintf(", %d ignored", rep.Ignored)
	}
	if rep.Strict {
		extra += " (strict)"
	}
	fmt.Fprintf(w, "%s: %d failed, %d warnings, %d info%s\n", verdict, fail, warn, info, extra)
}

func printAdvisories(w io.Writer, db *agent.DB, asJSON bool) {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		_ = enc.Encode(db)
		return
	}
	fmt.Fprintf(w, "advisory database updated %s (sources: %s)\n", db.Updated, strings.Join(db.Sources, ", "))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  ID\tSTACK\tPACKAGES\tAFFECTED\tFIXED\tACTION")
	for _, a := range db.Advisories {
		pk := a.Packages
		if len(pk) == 0 {
			for _, s := range db.Stacks {
				if s.Name == a.Stack {
					pk = s.Packages
				}
			}
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n", a.ID, a.Stack, strings.Join(pk, ","), a.Affected, orDash(a.Fixed), a.Action)
	}
	tw.Flush()
}
