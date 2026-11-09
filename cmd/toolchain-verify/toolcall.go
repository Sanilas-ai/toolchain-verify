package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Sanilas-ai/toolchain-verify/internal/toolcall"
)

func cmdToolcall(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, `usage: toolchain-verify toolcall <parse|bench|grounded|profiles|stops> ...`)
		return 2
	}
	switch args[0] {
	case "parse":
		return cmdToolcallParse(args[1:], stdin, stdout, stderr)
	case "bench":
		return cmdToolcallBench(args[1:], stdout, stderr)
	case "grounded":
		return cmdToolcallGrounded(args[1:], stdin, stdout, stderr)
	case "profiles":
		return cmdToolcallProfiles(stdout, stderr)
	case "stops":
		return cmdToolcallStops(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, toolcallUsage)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown toolcall subcommand %q\n%s", args[0], toolcallUsage)
		return 2
	}
}

const toolcallUsage = `toolchain-verify toolcall — safe parser for small local tool-call models

Usage:
  toolchain-verify toolcall parse  --profile ID|FILE --tools tools.json
                                   [--approve|--no-tty] [--exfil] [--json]
                                   [FILE|-]
  toolchain-verify toolcall bench  --profile ID|FILE --tools tools.json DIR
                                   [--json] [--recursive]
  toolchain-verify toolcall grounded [--source FILE] [--json] [FILE|-]
  toolchain-verify toolcall profiles
  toolchain-verify toolcall stops --profile ID|FILE

Profiles (embedded): lfm3, lfm2, minicpm5, hermes.
parse keeps the FIRST complete valid call and drops trailing junk.
Sensitive tool classes (network, secrets, wallet, file_write, file_delete,
shell, eval, env) need a human 'yes' on /dev/tty unless --approve (tests)
or are denied by default with --no-tty / no terminal.
`

func cmdToolcallProfiles(stdout, stderr io.Writer) int {
	m, err := toolcall.BuiltinProfiles()
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	for _, id := range sortedKeys(m) {
		p := m[id]
		fmt.Fprintf(stdout, "%-10s  %-16s  start=%q end=%q\n", p.ID, p.Format, p.CallStart, p.CallEnd)
		fmt.Fprintf(stdout, "            stops: %s\n", strings.Join(p.StopSequences, ", "))
		for _, s := range p.Sources {
			fmt.Fprintf(stdout, "            src: %s\n", s)
		}
	}
	return 0
}

func sortedKeys(m map[string]toolcall.Profile) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	// tiny insertion sort to avoid importing sort in this file only — use sort
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && ids[j] < ids[j-1]; j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
	return ids
}

func cmdToolcallStops(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("toolcall stops", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profile := fs.String("profile", "", "profile id or TOML path")
	asJSON := fs.Bool("json", false, "JSON array")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *profile == "" {
		fmt.Fprintln(stderr, "error: --profile is required")
		return 2
	}
	p, err := toolcall.LoadProfile(*profile)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if *asJSON {
		writeJSON(stdout, p.StopSequences)
		return 0
	}
	for _, s := range p.StopSequences {
		fmt.Fprintln(stdout, s)
	}
	return 0
}

func cmdToolcallParse(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("toolcall parse", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profile := fs.String("profile", "", "profile id (lfm3|lfm2|minicpm5|hermes) or TOML path")
	toolsPath := fs.String("tools", "", "JSON array of allowlisted tools (+ schemas)")
	asJSON := fs.Bool("json", false, "JSON result")
	approve := fs.Bool("approve", false, "auto-approve sensitive tools (tests only)")
	noTTY := fs.Bool("no-tty", false, "deny sensitive tools instead of asking on /dev/tty")
	exfil := fs.Bool("exfil", true, "reject .env / secret-looking arguments (Log-To-Leak)")
	timeout := fs.Duration("timeout", 2*time.Minute, "TTY approval timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *profile == "" || *toolsPath == "" {
		fmt.Fprintln(stderr, "error: --profile and --tools are required")
		return 2
	}
	p, err := toolcall.LoadProfile(*profile)
	if err != nil {
		fmt.Fprintln(stderr, "error: profile:", err)
		return 2
	}
	tools, err := loadTools(*toolsPath)
	if err != nil {
		fmt.Fprintln(stderr, "error: tools:", err)
		return 2
	}
	input, err := readInput(fs.Arg(0), stdin)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	var approver toolcall.Approver = toolcall.DenyAll{}
	switch {
	case *approve:
		approver = toolcall.AllowAll{}
	case *noTTY:
		approver = toolcall.DenyAll{}
	default:
		approver = toolcall.TTY{Timeout: *timeout}
	}
	ctx := context.Background()
	res := toolcall.Parse(ctx, string(input), toolcall.Options{
		Profile:    p,
		Tools:      tools,
		Approver:   approver,
		CheckExfil: *exfil,
	})
	if *asJSON {
		writeJSON(stdout, res)
		return mapStatus(res)
	}
	printToolcall(stdout, res)
	switch res.Status {
	case toolcall.StatusOK:
		return 0
	case toolcall.StatusNoCall, toolcall.StatusTruncated, toolcall.StatusInvalidJSON, toolcall.StatusSchema, toolcall.StatusParseError, toolcall.StatusHiddenUnicode:
		return 1
	default:
		return 1
	}
}

func cmdToolcallBench(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("toolcall bench", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profile := fs.String("profile", "", "profile id or TOML path")
	toolsPath := fs.String("tools", "", "JSON tools allowlist")
	asJSON := fs.Bool("json", false, "JSON report")
	recursive := fs.Bool("recursive", false, "walk subdirectories")
	note := fs.String("runtime-note", "", "record runtime version (llama.cpp/Ollama); required for live benches")
	approve := fs.Bool("approve", true, "auto-approve sensitive tools during bench (default true)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *profile == "" || *toolsPath == "" || fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: toolchain-verify toolcall bench --profile ID --tools tools.json DIR")
		return 2
	}
	p, err := toolcall.LoadProfile(*profile)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	tools, err := loadTools(*toolsPath)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	var approver toolcall.Approver = toolcall.DenyAll{}
	if *approve {
		approver = toolcall.AllowAll{}
	}
	rep, err := toolcall.BenchDir(context.Background(), fs.Arg(0), toolcall.Options{
		Profile: p, Tools: tools, Approver: approver, CheckExfil: true,
	}, *recursive)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	rep.RuntimeNote = *note
	if *asJSON {
		writeJSON(stdout, rep)
		return 0
	}
	fmt.Fprintf(stdout, "toolcall bench: %s profile=%s\n", rep.Dir, rep.ProfileID)
	if rep.RuntimeNote != "" {
		fmt.Fprintf(stdout, "  runtime: %s\n", rep.RuntimeNote)
	}
	fmt.Fprintf(stdout, "  total=%d ok=%d trailing_junk=%d stopped_clean=%d schema=%d disallowed=%d other=%d\n",
		rep.Total, rep.ParsedOK, rep.TrailingJunk, rep.StoppedClean, rep.SchemaFail, rep.Disallowed, rep.OtherFail)
	fmt.Fprintf(stdout, "  parse_rate=%.3f stop_clean_rate=%.3f valid_rate=%.3f\n",
		rep.ParseRate, rep.StopCleanRate, rep.ValidRate)
	return 0
}

func cmdToolcallGrounded(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("toolcall grounded", flag.ContinueOnError)
	fs.SetOutput(stderr)
	source := fs.String("source", "", "optional source text to verify the verbatim quote")
	asJSON := fs.Bool("json", false, "JSON result")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	input, err := readInput(fs.Arg(0), stdin)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	src := ""
	if *source != "" {
		b, err := os.ReadFile(*source)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		src = string(b)
	}
	gr := toolcall.ValidateGrounded(string(input), src)
	if *asJSON {
		writeJSON(stdout, gr)
		if gr.OK {
			return 0
		}
		return 1
	}
	if gr.OK {
		if gr.Answer.NotFound {
			fmt.Fprintln(stdout, "PASS: not found (exact refusal)")
		} else {
			fmt.Fprintf(stdout, "PASS: answer ok")
			if src != "" {
				fmt.Fprintf(stdout, ", quote_verified=%v", gr.QuoteVerified)
			}
			fmt.Fprintln(stdout)
		}
		return 0
	}
	fmt.Fprintf(stdout, "FAIL: %s\n", gr.Error)
	return 1
}

func loadTools(path string) ([]toolcall.ToolSpec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var tools []toolcall.ToolSpec
	if err := json.Unmarshal(b, &tools); err != nil {
		return nil, err
	}
	return tools, nil
}

func printToolcall(w io.Writer, res *toolcall.Result) {
	fmt.Fprintf(w, "toolchain-verify toolcall: status=%s profile=%s trailing_junk=%v\n",
		res.Status, res.ProfileID, res.TrailingJunk)
	if res.Call != nil {
		fmt.Fprintf(w, "  call: %s class=%s\n", res.Call.Name, res.Call.Class)
		fmt.Fprintf(w, "  args: %s", toolcall.PrettyJSON(res.Call.Arguments))
	}
	if res.TrailingJunk {
		fmt.Fprintf(w, "  dropped_bytes=%d preview=%q\n", res.DroppedBytes, res.TrailingPreview)
	}
	for _, h := range res.HiddenUnicode {
		fmt.Fprintf(w, "  hidden: %s\n", h)
	}
	if res.ModelError != nil {
		fmt.Fprintf(w, "  model_error: %s\n", res.ModelError.String())
	}
	if len(res.StopSequences) > 0 {
		fmt.Fprintf(w, "  recommended_stops: %s\n", strings.Join(res.StopSequences, " | "))
	}
}

func mapStatus(res *toolcall.Result) int {
	switch res.Status {
	case toolcall.StatusOK:
		return 0
	default:
		return 1
	}
}
