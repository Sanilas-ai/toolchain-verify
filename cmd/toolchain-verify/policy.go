package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Sanilas-ai/toolchain-verify/internal/execpolicy"
	"github.com/Sanilas-ai/toolchain-verify/internal/manifest"
)

// PolicyEnv names the environment variable with the exec policy path.
const PolicyEnv = "TOOLCHAIN_VERIFY_POLICY"

// loadExecPolicy finds the exec policy: -m, $TOOLCHAIN_VERIFY_POLICY,
// ~/.config/toolchain-verify/exec-policy.toml, then ./toolchain.toml
// (only from a trusted cwd).
func loadExecPolicy(fs *flag.FlagSet, path, cwd, home string, stderr io.Writer) (*execpolicy.Policy, string, error) {
	try := func(p string) (*execpolicy.Policy, string, error) {
		m, err := manifest.Load(p)
		if err != nil {
			return nil, p, err
		}
		if m.ExecPolicy == nil {
			return nil, p, fmt.Errorf("%s: no [exec_policy] section", p)
		}
		return m.ExecPolicy, p, nil
	}
	if flagSet(fs, "m", "manifest") {
		return try(path)
	}
	if p := os.Getenv(PolicyEnv); p != "" {
		return try(p)
	}
	if home != "" {
		p := filepath.Join(home, ".config", "toolchain-verify", "exec-policy.toml")
		if _, err := os.Stat(p); err == nil {
			return try(p)
		}
	}
	m, err := policyManifest(fs, path, cwd, home, stderr)
	if err != nil {
		return nil, path, err
	}
	if m == nil || m.ExecPolicy == nil {
		return nil, "", errors.New("no exec policy found (use -m FILE, $" + PolicyEnv + " or ~/.config/toolchain-verify/exec-policy.toml)")
	}
	return m.ExecPolicy, filepath.Join(m.Dir, manifest.DefaultFile), nil
}

func cmdPolicy(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "check" && args[0] != "validate") {
		fmt.Fprintln(stderr, "usage: toolchain-verify policy check [-m FILE] [--hook claude|cursor] [-c CMD]... [-- ARGV...]")
		fmt.Fprintln(stderr, "       toolchain-verify policy validate [-m FILE]")
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("policy "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("m", manifest.DefaultFile, "policy file (a manifest with an [exec_policy] section)")
	fs.StringVar(path, "manifest", manifest.DefaultFile, "policy file (a manifest with an [exec_policy] section)")
	var cmds multiFlag
	fs.Var(&cmds, "c", "shell command line to check (repeatable)")
	hook := fs.String("hook", "", "read the command from a hook payload on stdin: \"claude\" (PreToolUse) or \"cursor\" (beforeShellExecution)")
	cwdFlag := fs.String("cwd", "", "working directory of the command (default: current, or the hook payload's cwd)")
	inSandbox := fs.Bool("in-sandbox", false, "treat the command as running inside the sandbox")
	onHost := fs.Bool("on-host", false, "treat the command as running on the host (ignore in-sandbox markers)")
	asJSON := fs.Bool("json", false, "print the decision as JSON")
	quiet := fs.Bool("q", false, "print nothing when the command is allowed")
	fs.BoolVar(quiet, "quiet", false, "print nothing when the command is allowed")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	cwd, home := cwdHome()
	pol, src, err := loadExecPolicy(fs, *path, cwd, home, stderr)
	if sub == "validate" {
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		fmt.Fprintf(stdout, "%s: exec policy OK (%d rules)\n", src, len(pol.Rules))
		return 0
	}
	if *hook != "" && *hook != "claude" && *hook != "cursor" {
		fmt.Fprintf(stderr, "error: --hook must be claude or cursor\n")
		return 2
	}
	if err != nil {
		// Fail closed: a hook without a policy blocks.
		return hookError(*hook, err, stdout, stderr)
	}
	var inputs []execpolicy.Input
	if *cwdFlag != "" {
		cwd = *cwdFlag
	}
	switch {
	case *hook != "":
		in, skip, err := readHook(*hook, stdin)
		if err != nil {
			return hookError(*hook, err, stdout, stderr)
		}
		if skip {
			if *hook == "cursor" {
				writeJSON(stdout, map[string]string{"permission": "allow"})
			}
			return 0
		}
		if in.Cwd == "" || *cwdFlag != "" {
			in.Cwd = cwd
		}
		inputs = append(inputs, in)
	case len(cmds) > 0:
		for _, c := range cmds {
			inputs = append(inputs, execpolicy.Input{Command: c, Cwd: cwd})
		}
	case fs.NArg() > 0:
		inputs = append(inputs, execpolicy.Input{Argv: fs.Args(), Cwd: cwd})
	default:
		fmt.Fprintln(stderr, "error: nothing to check (use -c CMD, -- ARGV..., or --hook)")
		return 2
	}
	var force *bool
	switch {
	case *inSandbox && *onHost:
		fmt.Fprintln(stderr, "error: --in-sandbox and --on-host are mutually exclusive")
		return 2
	case *inSandbox:
		t := true
		force = &t
	case *onHost:
		f := false
		force = &f
	}
	code := 0
	var decisions []execpolicy.Decision
	for _, in := range inputs {
		in.Home, in.InSandbox = home, force
		d := execpolicy.Check(pol, in)
		decisions = append(decisions, d)
		if !d.Allowed {
			code = 1
		}
	}
	switch *hook {
	case "claude":
		// PreToolUse: exit 2 blocks the tool call and shows stderr to the model.
		if code != 0 {
			fmt.Fprintln(stderr, denyMessage(decisions[0]))
			return 2
		}
		return 0
	case "cursor":
		d := decisions[0]
		if d.Allowed {
			writeJSON(stdout, map[string]string{"permission": "allow"})
		} else {
			msg := denyMessage(d)
			writeJSON(stdout, map[string]string{"permission": "deny", "user_message": msg, "agent_message": msg})
		}
		return 0
	}
	if *asJSON {
		if len(decisions) == 1 {
			writeJSON(stdout, decisions[0])
		} else {
			writeJSON(stdout, decisions)
		}
		return code
	}
	for _, d := range decisions {
		if *quiet && d.Allowed {
			continue
		}
		state := "ALLOW"
		if !d.Allowed {
			state = "BLOCK"
		}
		where := d.Verdict
		if d.InSandbox {
			where += ", in sandbox"
		}
		fmt.Fprintf(stdout, "%s  [%s] %s\n", state, where, d.Command)
		for _, s := range d.Commands {
			label := s.Program
			if s.Wrapped {
				label += " (sandboxed)"
			}
			fmt.Fprintf(stdout, "       %-7s %s: %s\n", s.Verdict, label, s.Reason)
		}
		if d.Hint != "" {
			fmt.Fprintf(stdout, "       hint: %s\n", d.Hint)
		}
		if d.Reason != "" && len(d.Commands) == 0 {
			fmt.Fprintf(stdout, "       %s\n", d.Reason)
		}
	}
	return code
}

func denyMessage(d execpolicy.Decision) string {
	msg := "toolchain-verify policy: blocked on the host (" + d.Verdict + "): " + d.Command
	if d.Reason != "" {
		msg += " — " + d.Reason
	}
	if d.Hint != "" {
		msg += "; " + d.Hint
	}
	return msg
}

func hookError(hook string, err error, stdout, stderr io.Writer) int {
	msg := "toolchain-verify policy: " + err.Error()
	switch hook {
	case "claude":
		fmt.Fprintln(stderr, msg)
		return 2
	case "cursor":
		writeJSON(stdout, map[string]string{"permission": "deny", "user_message": msg, "agent_message": msg})
		return 0
	}
	fmt.Fprintln(stderr, "error:", err)
	return 2
}

// readHook decodes a hook payload. skip is true for non-shell tools.
func readHook(kind string, stdin io.Reader) (execpolicy.Input, bool, error) {
	data, err := io.ReadAll(io.LimitReader(stdin, 1<<20))
	if err != nil {
		return execpolicy.Input{}, false, err
	}
	var p struct {
		ToolName  string `json:"tool_name"`
		ToolInput struct {
			Command          string `json:"command"`
			WorkingDirectory string `json:"working_directory"`
		} `json:"tool_input"`
		Command string `json:"command"`
		Cwd     string `json:"cwd"`
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return execpolicy.Input{}, false, fmt.Errorf("bad %s hook payload: %w", kind, err)
	}
	in := execpolicy.Input{Command: p.Command, Cwd: p.Cwd}
	if p.ToolName != "" || p.ToolInput.Command != "" {
		switch p.ToolName {
		case "", "Bash", "Shell", "run_terminal_cmd":
		default:
			return in, true, nil
		}
		in.Command = p.ToolInput.Command
		if p.ToolInput.WorkingDirectory != "" {
			in.Cwd = p.ToolInput.WorkingDirectory
		}
	}
	if strings.TrimSpace(in.Command) == "" {
		return in, false, errors.New("hook payload has no command")
	}
	return in, false, nil
}
