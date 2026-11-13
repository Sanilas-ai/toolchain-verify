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
	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
	"github.com/Sanilas-ai/toolchain-verify/internal/manifest"
)

// Shared helpers for the audits that report findings.Finding values.

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
		if len(f.CWE) > 0 && verbose {
			fmt.Fprintf(w, "        cwe: %s\n", strings.Join(f.CWE, ", "))
		}
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
