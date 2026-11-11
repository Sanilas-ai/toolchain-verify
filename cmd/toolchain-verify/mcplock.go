package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Sanilas-ai/toolchain-verify/internal/agent"
	"github.com/Sanilas-ai/toolchain-verify/internal/check"
	"github.com/Sanilas-ai/toolchain-verify/internal/manifest"
	"github.com/Sanilas-ai/toolchain-verify/internal/reposcan"
)

// cmdMCPLock records or verifies an MCP server lock (package + exact version
// + integrity hash per server), optionally pinning tool-definition hashes.
func cmdMCPLock(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp-lock", flag.ContinueOnError)
	fs.SetOutput(stderr)
	write := fs.String("write", "", "write the lock for the current configs to FILE")
	lockFile := fs.String("lock", "", "verify the current configs against FILE")
	toolsFile := fs.String("tools", "", "a saved MCP tools/list result to pin (rug-pull detection)")
	path := fs.String("m", manifest.DefaultFile, "manifest with an [agent] section (optional)")
	fs.StringVar(path, "manifest", manifest.DefaultFile, "manifest with an [agent] section (optional)")
	var trusted multiFlag
	fs.Var(&trusted, "trusted", "trusted project root (repeatable)")
	home := fs.String("home", "", "home directory (default: current user's)")
	cwdFlag := fs.String("cwd", "", "working directory (default: current)")
	asJSON := fs.Bool("json", false, "print a JSON report")
	strict := fs.Bool("strict", false, "warnings fail the run")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if (*write == "") == (*lockFile == "") {
		fmt.Fprintln(stderr, "usage: toolchain-verify mcp-lock (--write FILE | --lock FILE) [--tools TOOLS.json] [-m manifest] [--trusted DIR]... [--json] [--strict]")
		return 2
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
	opt := agent.Options{Home: h, Cwd: cwd, InContainer: check.DetectContainer(), ExtraTrusted: trusted, NoHostInventory: true}
	var pol *agent.Policy
	if flagSet(fs, "m", "manifest") {
		m, err := manifest.Load(*path)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		pol = m.Agent
		opt.RequireContainer = m.RequireContainer
		opt.ManifestDir = m.Dir
	}
	servers, err := agent.CollectMCPServers(pol, opt)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}

	if *write != "" {
		lock := agent.NewMCPLock(servers, time.Now().UTC().Format(time.RFC3339))
		if *toolsFile != "" {
			tools, err := loadToolHashes(*toolsFile)
			if err != nil {
				fmt.Fprintln(stderr, "error:", err)
				return 2
			}
			lock.Tools = tools
		}
		out, _ := json.MarshalIndent(lock, "", "  ")
		if err := os.WriteFile(*write, append(out, '\n'), 0o644); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		fmt.Fprintf(stdout, "wrote %s: %d server(s), %d tool hash(es)\n", *write, len(lock.Servers), len(lock.Tools))
		return 0
	}

	lock, err := agent.LoadMCPLock(*lockFile)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	findings := agent.CheckMCPLock(lock, servers)
	if *toolsFile != "" && len(lock.Tools) > 0 {
		tf, err := rugPullFindings(*toolsFile, lock.Tools)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		findings = append(findings, tf...)
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		_ = enc.Encode(map[string]any{"lock": *lockFile, "findings": findings})
	} else {
		printLockFindings(stdout, *lockFile, findings)
	}
	fail, warn := 0, 0
	for _, f := range findings {
		switch f.Severity {
		case agent.SevFail:
			fail++
		case agent.SevWarn:
			warn++
		}
	}
	if fail > 0 || (*strict && warn > 0) {
		return 1
	}
	return 0
}

func loadToolHashes(path string) (map[string]string, error) {
	b, err := readCapped(path, 16<<20)
	if err != nil {
		return nil, err
	}
	_, tools, err := reposcan.LintMCPTools(b, nil)
	if err != nil {
		return nil, err
	}
	return reposcan.NewToolPin(tools, "").Tools, nil
}

func rugPullFindings(path string, pinned map[string]string) ([]agent.Finding, error) {
	b, err := readCapped(path, 16<<20)
	if err != nil {
		return nil, err
	}
	rep, _, err := reposcan.LintMCPTools(b, &reposcan.ToolPin{Version: 1, Tools: pinned})
	if err != nil {
		return nil, err
	}
	var out []agent.Finding
	for _, f := range rep.Findings {
		switch f.Rule {
		case "mcp.rug-pull", "mcp.tool-new", "mcp.tool-removed":
			out = append(out, agent.Finding{Rule: f.Rule, Severity: f.Severity, Path: f.Path, Message: f.Message})
		}
	}
	return out, nil
}

func printLockFindings(w io.Writer, lockFile string, findings []agent.Finding) {
	fmt.Fprintf(w, "toolchain-verify mcp-lock: %s\n", lockFile)
	fail, warn, info := 0, 0, 0
	for _, f := range findings {
		switch f.Severity {
		case agent.SevFail:
			fail++
		case agent.SevWarn:
			warn++
		default:
			info++
		}
		fmt.Fprintf(w, "  %-4s  %-18s %s\n", upper(f.Severity), f.Rule, orDash(f.Path))
		fmt.Fprintf(w, "        %s\n", f.Message)
		if f.Fix != "" {
			fmt.Fprintf(w, "        fix: %s\n", f.Fix)
		}
	}
	verdict := "PASS"
	if fail > 0 {
		verdict = "FAIL"
	}
	fmt.Fprintf(w, "%s: %d failed, %d warnings, %d info\n", verdict, fail, warn, info)
}

func upper(s string) string {
	switch s {
	case agent.SevFail:
		return "FAIL"
	case agent.SevWarn:
		return "WARN"
	}
	return "INFO"
}
