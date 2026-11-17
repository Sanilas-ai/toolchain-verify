package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Sanilas-ai/toolchain-verify/internal/check"
	"github.com/Sanilas-ai/toolchain-verify/internal/execpolicy"
	"github.com/Sanilas-ai/toolchain-verify/internal/manifest"
	"github.com/Sanilas-ai/toolchain-verify/internal/pipeline"
	"github.com/Sanilas-ai/toolchain-verify/internal/toolcall"
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
	follow := fs.Bool("follow-script", false, "read one script file inside the working directory and judge it (bash/sh/python/node)")
	mediateLog := fs.String("mediate-log", "", "append-only mediator record outside the repository")
	sessionID := fs.String("session", "", "session id written on the mediator line")
	repo := fs.String("repo", "", "repository root for the subject (default: cwd)")
	var trusted, allowSubj multiFlag
	fs.Var(&trusted, "trusted", "trusted root for path arguments (repeatable)")
	fs.Var(&allowSubj, "allow-subject", "uid=N,container=true|false,repo=PATH (repeatable; empty means no subject gate)")
	approve := fs.Bool("approve", false, "human already approved a shell allow (tests); otherwise a hook asks on /dev/tty")
	ttyPath := fs.String("tty-file", "/dev/tty", "terminal used for a shell allow")
	asJSON := fs.Bool("json", false, "print the decision as JSON")
	quiet := fs.Bool("q", false, "print nothing when the command is allowed")
	fs.BoolVar(quiet, "quiet", false, "print nothing when the command is allowed")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	cwd, home := cwdHome()
	pol, src, policyErr := loadExecPolicy(fs, *path, cwd, home, stderr)
	if sub == "validate" {
		if policyErr != nil {
			fmt.Fprintln(stderr, "error:", policyErr)
			return 2
		}
		fmt.Fprintf(stdout, "%s: exec policy OK (%d rules)\n", src, len(pol.Rules))
		return 0
	}
	if *hook != "" && *hook != "claude" && *hook != "cursor" && *hook != "claude-post" && *hook != "cursor-post" {
		fmt.Fprintf(stderr, "error: --hook must be claude, cursor, claude-post or cursor-post\n")
		return 2
	}
	if *repo == "" {
		*repo = cwd
	}
	subj := pipeline.Subject{UID: os.Getuid(), Container: check.DetectContainer(), Repo: *repo, Session: *sessionID}
	var allows []pipeline.Subject
	for _, spec := range allowSubj {
		parsed, err := pipeline.ParseSubject(spec)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		allows = append(allows, parsed)
	}
	var med *pipeline.Log
	if *mediateLog != "" {
		var err error
		med, err = pipeline.OpenLog(*mediateLog, *repo)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
	}
	statePath := ""
	if med != nil {
		statePath = *mediateLog + ".state"
	}
	if *hook == "claude-post" || *hook == "cursor-post" {
		return cmdPostHook(*hook, stdin, stdout, stderr, med, subj, statePath)
	}
	if policyErr != nil {
		// Fail closed: a hook without a policy blocks.
		_ = appendRecord(med, pipeline.Record{Rule: "execpolicy", Verdict: "deny", Tool: "shell", Subject: subj})
		return hookError(*hook, policyErr, stdout, stderr)
	}
	var inputs []execpolicy.Input
	var shell hookCall
	if *cwdFlag != "" {
		cwd = *cwdFlag
	}
	switch {
	case *hook != "":
		call, err := readHook(*hook, stdin)
		if err != nil {
			_ = appendRecord(med, pipeline.Record{Rule: "execpolicy", Verdict: "deny", Tool: "shell", Subject: subj})
			return hookError(*hook, err, stdout, stderr)
		}
		shell = call
		if call.skipPolicy {
			rec := judgeCall(call, nil, subj, allows, []string(trusted), home, statePath, false, *ttyPath)
			if err := appendRecord(med, rec); err != nil {
				fmt.Fprintln(stderr, "error:", err)
				return hookError(*hook, err, stdout, stderr)
			}
			return emitHook(*hook, rec.Verdict == "allow", "toolchain-verify policy: blocked ("+rec.Rule+")", stdout, stderr)
		}
		if call.in.Cwd == "" || *cwdFlag != "" {
			call.in.Cwd = cwd
		}
		inputs = append(inputs, call.in)
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
		in.Home, in.InSandbox, in.FollowScript = home, force, *follow
		d := execpolicy.Check(pol, in)
		decisions = append(decisions, d)
		if !d.Allowed {
			code = 1
		}
	}
	if *hook == "claude" || *hook == "cursor" {
		d := decisions[0]
		rec := judgeCall(shell, &d, subj, allows, []string(trusted), home, statePath, *approve, *ttyPath)
		if err := appendRecord(med, rec); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return hookError(*hook, err, stdout, stderr)
		}
		msg := denyMessage(d)
		if rec.Rule != "execpolicy" {
			msg = "toolchain-verify policy: blocked (" + rec.Rule + ")"
		}
		return emitHook(*hook, rec.Verdict == "allow", msg, stdout, stderr)
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

// hookCall is one proposed tool call. args is judged and never written to
// the mediator log.
type hookCall struct {
	in         execpolicy.Input
	skipPolicy bool
	name       string
	id         string
	args       string
}

// readHook decodes a pre-tool payload. Non-shell tools skip execpolicy and
// are judged on their arguments.
func readHook(kind string, stdin io.Reader) (hookCall, error) {
	data, err := io.ReadAll(io.LimitReader(stdin, 1<<20))
	if err != nil {
		return hookCall{}, err
	}
	var p struct {
		ToolName  string `json:"tool_name"`
		ToolUseID string `json:"tool_use_id"`
		ToolInput struct {
			Command          string `json:"command"`
			WorkingDirectory string `json:"working_directory"`
			FilePath         string `json:"file_path"`
			Path             string `json:"path"`
		} `json:"tool_input"`
		Command string `json:"command"`
		Cwd     string `json:"cwd"`
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return hookCall{}, fmt.Errorf("bad %s hook payload: %w", kind, err)
	}
	call := hookCall{name: p.ToolName, id: p.ToolUseID, in: execpolicy.Input{Command: p.Command, Cwd: p.Cwd}}
	if call.name == "" {
		call.name = "shell"
	}
	if p.ToolName != "" || p.ToolInput.Command != "" || p.ToolInput.FilePath != "" || p.ToolInput.Path != "" {
		call.args = strings.TrimSpace(strings.Join([]string{p.ToolInput.Command, p.ToolInput.FilePath, p.ToolInput.Path}, " "))
		if pipeline.ClassOf(p.ToolName) != "shell" && p.ToolName != "" {
			call.skipPolicy = true
			return call, nil
		}
		call.in.Command = p.ToolInput.Command
		if p.ToolInput.WorkingDirectory != "" {
			call.in.Cwd = p.ToolInput.WorkingDirectory
		}
	}
	if call.args == "" {
		call.args = call.in.Command
	}
	if strings.TrimSpace(call.in.Command) == "" {
		return hookCall{}, errors.New("hook payload has no command")
	}
	return call, nil
}

// judgeCall applies argument, flow, policy, subject and tty gates. The
// record it returns contains no argument text.
func judgeCall(call hookCall, d *execpolicy.Decision, subj pipeline.Subject, allows []pipeline.Subject, trusted []string, home, statePath string, approve bool, ttyPath string) pipeline.Record {
	tool := call.name
	if tool == "" {
		tool = "shell"
	}
	rec := pipeline.Record{Rule: "execpolicy", Verdict: "deny", Tool: tool, Subject: subj}
	if why := pipeline.BadArgument(call.args, home, trusted); why != "" {
		rec.Rule = "pipeline.path"
		return rec
	}
	if id, ok := pipeline.Flow(statePath, call.args); ok {
		rec.Rule = "pipeline.flow"
		rec.Source = id
		return rec
	}
	if call.skipPolicy {
		if pipeline.ClassOf(tool) == "other" {
			rec.Rule = "pipeline.class"
			return rec
		}
		rec.Rule = "pipeline.args"
		rec.Verdict = "allow"
		return rec
	}
	if d == nil || !d.Allowed {
		rec.Rule = "execpolicy"
		return rec
	}
	if !pipeline.Allows(subj, allows) {
		rec.Rule = "pipeline.subject"
		return rec
	}
	if !approve {
		ok, err := (toolcall.TTY{Path: ttyPath}).Approve(context.Background(), toolcall.Call{
			Name: tool, Class: "shell", Arguments: map[string]interface{}{"command": call.args},
		})
		if err != nil || !ok {
			rec.Rule = "pipeline.tty"
			return rec
		}
	}
	rec.Verdict = "allow"
	return rec
}

func appendRecord(med *pipeline.Log, rec pipeline.Record) error {
	if med == nil {
		return nil
	}
	return med.Append(rec)
}

func emitHook(hook string, allow bool, msg string, stdout, stderr io.Writer) int {
	switch hook {
	case "claude", "claude-post":
		if !allow {
			fmt.Fprintln(stderr, msg)
			return 2
		}
		return 0
	case "cursor", "cursor-post":
		if allow {
			writeJSON(stdout, map[string]string{"permission": "allow"})
		} else {
			writeJSON(stdout, map[string]string{"permission": "deny", "user_message": msg, "agent_message": msg})
		}
		return 0
	}
	fmt.Fprintln(stderr, msg)
	return 2
}

func cmdPostHook(kind string, stdin io.Reader, stdout, stderr io.Writer, med *pipeline.Log, subj pipeline.Subject, statePath string) int {
	data, err := io.ReadAll(io.LimitReader(stdin, 1<<20))
	if err != nil {
		return hookError(kind, err, stdout, stderr)
	}
	var p struct {
		ToolName     string          `json:"tool_name"`
		ToolUseID    string          `json:"tool_use_id"`
		ToolResponse json.RawMessage `json:"tool_response"`
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return hookError(kind, fmt.Errorf("bad %s hook payload: %w", kind, err), stdout, stderr)
	}
	text := string(p.ToolResponse)
	var asString string
	if json.Unmarshal(p.ToolResponse, &asString) == nil {
		text = asString
	}
	rec := pipeline.Record{Rule: "pipeline.scrub", Verdict: "allow", Tool: p.ToolName, Subject: subj, Source: p.ToolUseID}
	if rule := pipeline.ScrubResult(text); rule != "" {
		rec.Verdict = "deny"
		rec.Rule = rule
	}
	if pipeline.ClassOf(p.ToolName) == "untrusted" {
		remErr := pipeline.Remember(statePath, p.ToolUseID, text)
		if rec.Verdict == "allow" && (statePath == "" || remErr != nil) {
			rec.Verdict = "deny"
			rec.Rule = "pipeline.flow"
		}
	}
	if err := appendRecord(med, rec); err != nil {
		return hookError(kind, err, stdout, stderr)
	}
	return emitHook(kind, rec.Verdict == "allow", "toolchain-verify policy: blocked ("+rec.Rule+")", stdout, stderr)
}
