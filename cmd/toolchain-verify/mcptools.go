package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Sanilas-ai/toolchain-verify/internal/reposcan"
)

// cmdMCPTools lints a saved MCP tools/list result offline.
func cmdMCPTools(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp-tools", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "print a JSON report")
	asSARIF := fs.Bool("sarif", false, "print SARIF 2.1.0")
	verbose := fs.Bool("v", false, "also print info findings and tool hashes")
	strict := fs.Bool("strict", false, "warnings fail too")
	pinFile := fs.String("pin", "", "approved tool hashes; changed definitions fail (rug pull)")
	writePin := fs.String("write-pin", "", "write hashes of the current tools to FILE (after review)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: toolchain-verify mcp-tools [--pin FILE] [--write-pin FILE] [--json|--sarif] TOOLS.json|-")
		return 2
	}
	var b []byte
	var err error
	if fs.Arg(0) == "-" {
		b, err = io.ReadAll(io.LimitReader(stdin, 16<<20))
	} else {
		b, err = readCapped(fs.Arg(0), 16<<20)
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	var pin *reposcan.ToolPin
	if *pinFile != "" {
		if pin, err = reposcan.LoadToolPin(*pinFile); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
	}
	rep, tools, err := reposcan.LintMCPTools(b, pin)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	rep.Root = fs.Arg(0)
	if *writePin != "" {
		out, _ := json.MarshalIndent(reposcan.NewToolPin(tools, time.Now().UTC().Format(time.RFC3339)), "", "  ")
		if err := os.WriteFile(*writePin, append(out, '\n'), 0o644); err != nil {
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
		printScan(stdout, rep, *verbose)
	}
	switch rep.Verdict {
	case reposcan.VerdictFail:
		return 1
	case reposcan.VerdictWarn:
		if *strict {
			return 1
		}
	}
	return 0
}

func readCapped(p string, max int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err == nil && int64(len(b)) > max {
		return nil, fmt.Errorf("%s: larger than %d bytes", p, max)
	}
	return b, err
}
