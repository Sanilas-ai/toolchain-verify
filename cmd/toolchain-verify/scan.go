package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Sanilas-ai/toolchain-verify/internal/reposcan"
)

// exitIncomplete: the scan could not look at everything it should have
// (limits, unreadable/unparsable control files, symlink escapes). Never a
// PASS.
const exitIncomplete = 4

func cmdScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "print a JSON report")
	asSARIF := fs.Bool("sarif", false, "print SARIF 2.1.0")
	verbose := fs.Bool("v", false, "also print info findings and the control-file inventory")
	quiet := fs.Bool("q", false, "print nothing on PASS")
	strict := fs.Bool("strict", false, "warnings fail too (exit 1)")
	baseline := fs.String("baseline", "", "approved control-file inventory (JSON) to diff against")
	writeBaseline := fs.String("write-baseline", "", "write the current control-file inventory to FILE (after you reviewed it)")
	reviewer := fs.String("reviewer", "", "name recorded in --write-baseline")
	var iocs, ignore multiFlag
	fs.Var(&iocs, "ioc", "extra IOC TOML file (repeatable)")
	fs.Var(&ignore, "ignore", "ignore RULE or RULE:PATH-GLOB (repeatable; never read from the repo)")
	maxFile := fs.Int64("max-file-size", 1<<20, "bytes read per file")
	maxFiles := fs.Int("max-files", 200000, "directory entries visited")
	maxDepth := fs.Int("max-depth", 40, "directory depth")
	maxTotal := fs.Int64("max-total", 1<<30, "total bytes read")
	timeout := fs.Duration("timeout", 5*time.Minute, "wall-clock limit")
	includeDeps := fs.Bool("include-deps", false, "also scan node_modules, .venv, vendor, ...")
	strictCov := fs.Bool("strict-coverage", false, "unscanned images/archives/binaries make the result INCOMPLETE")
	listIOCs := fs.Bool("list-iocs", false, "print the IOC database and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	db, err := reposcan.LoadIOCs(iocs...)
	if err != nil {
		fmt.Fprintln(stderr, "error: ioc:", err)
		return 2
	}
	if *listIOCs {
		fmt.Fprintf(stdout, "IOC DB %s (updated %s)\n", db.Version, db.Updated)
		for _, e := range db.IOCs {
			fmt.Fprintf(stdout, "  %s  %s  [%s, %s]\n", e.ID, e.Title, e.Published, e.Source)
		}
		return 0
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: toolchain-verify scan [flags] DIR")
		return 2
	}
	opt := reposcan.Options{MaxFileSize: *maxFile, MaxFiles: *maxFiles, MaxDepth: *maxDepth, MaxTotal: *maxTotal,
		Timeout: *timeout, IncludeDeps: *includeDeps, IOCs: db, Ignore: ignore, StrictImages: *strictCov}
	if *baseline != "" {
		bl, err := reposcan.LoadBaseline(*baseline)
		if err != nil {
			fmt.Fprintln(stderr, "error: baseline:", err)
			return 2
		}
		opt.Baseline = bl
	}
	rep, err := reposcan.Scan(fs.Arg(0), opt)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		if errors.Is(err, reposcan.ErrRefused) {
			return 2
		}
		return 2
	}
	if *writeBaseline != "" {
		b, _ := json.MarshalIndent(reposcan.NewBaseline(rep, *reviewer), "", "  ")
		if err := os.WriteFile(*writeBaseline, append(b, '\n'), 0o644); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
	}
	switch {
	case *asSARIF:
		writeJSON(stdout, rep.SARIF(buildVersion))
	case *asJSON:
		writeJSON(stdout, rep)
	default:
		if !(*quiet && rep.Verdict == reposcan.VerdictPass) {
			printScan(stdout, rep, *verbose)
		}
	}
	switch rep.Verdict {
	case reposcan.VerdictFail:
		return 1
	case reposcan.VerdictIncomplete:
		return exitIncomplete
	case reposcan.VerdictWarn:
		if *strict {
			return 1
		}
	}
	return 0
}

func printScan(w io.Writer, rep *reposcan.Report, verbose bool) {
	fmt.Fprintf(w, "toolchain-verify scan: %s (IOC DB %s)\n", rep.Root, rep.IOCVersion)
	for _, f := range rep.Findings {
		if f.Severity == reposcan.SevInfo && !verbose {
			continue
		}
		loc := f.Path
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.Path, f.Line)
		}
		fmt.Fprintf(w, "  %-4s  %-28s %s\n", strings.ToUpper(f.Severity), f.Rule, orDash(loc))
		fmt.Fprintf(w, "        %s\n", f.Message)
		if f.Evidence != "" {
			fmt.Fprintf(w, "        evidence: %s\n", f.Evidence)
		}
		if f.Decoded != "" {
			fmt.Fprintf(w, "        decoded:  %s\n", f.Decoded)
		}
		if f.Fix != "" && (verbose || f.Severity == reposcan.SevFail) {
			fmt.Fprintf(w, "        fix: %s\n", f.Fix)
		}
	}
	if verbose {
		fmt.Fprintf(w, "  control files (%d):\n", len(rep.Inventory))
		for _, c := range rep.Inventory {
			fmt.Fprintf(w, "    %-14s %s\n", c.Kind, c.Path)
		}
	}
	cov := rep.Coverage
	var nc []string
	for k, v := range cov.NotChecked {
		nc = append(nc, fmt.Sprintf("%d %s", v, k))
	}
	sort.Strings(nc)
	fmt.Fprintf(w, "  coverage: %d entries, %d bytes read, %d control files", cov.Files, cov.BytesRead, len(rep.Inventory))
	if len(nc) > 0 {
		fmt.Fprintf(w, "; not checked: %s", strings.Join(nc, ", "))
	}
	if len(cov.PartialFiles) > 0 {
		fmt.Fprintf(w, "; %d large files scanned partially", len(cov.PartialFiles))
	}
	if len(cov.SkippedDirs) > 0 {
		fmt.Fprintf(w, "; %d dependency dirs skipped", len(cov.SkippedDirs))
	}
	fmt.Fprintln(w)
	for _, r := range cov.Incomplete {
		fmt.Fprintf(w, "  INCOMPLETE: %s\n", r)
	}
	fail, warn, info := rep.Counts()
	extra := ""
	if rep.Ignored > 0 {
		extra = fmt.Sprintf(", %d ignored", rep.Ignored)
	}
	fmt.Fprintf(w, "%s: %d failed, %d warnings, %d info%s\n", rep.Verdict, fail, warn, info, extra)
}
