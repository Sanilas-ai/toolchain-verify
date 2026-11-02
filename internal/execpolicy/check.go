package execpolicy

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Input is a proposed command.
type Input struct {
	// Command is a shell command line (parsed with SplitShell) ...
	Command string
	// ... or Argv an exact argument vector (used when Command is empty).
	Argv []string
	Cwd  string
	Home string
	// InSandbox forces the in-sandbox mode (nil: detect via markers).
	InSandbox *bool

	inSandbox bool
}

// Decision is the policy verdict for an Input.
type Decision struct {
	Command   string    `json:"command"`
	Verdict   string    `json:"verdict"` // host, sandbox, deny
	Allowed   bool      `json:"allowed"`
	InSandbox bool      `json:"in_sandbox"`
	Reason    string    `json:"reason,omitempty"`
	Hint      string    `json:"hint,omitempty"`
	Commands  []Segment `json:"commands"`
}

// Segment is the verdict for one simple command.
type Segment struct {
	Argv    []string `json:"argv"`
	Program string   `json:"program"` // innermost program after wrappers
	Verdict string   `json:"verdict"`
	Wrapped bool     `json:"sandboxed,omitempty"`
	Rule    int      `json:"rule,omitempty"` // 1-based rule index, 0 = default
	Reason  string   `json:"reason,omitempty"`
}

func rank(v string) int {
	switch v {
	case Deny:
		return 2
	case Sandbox:
		return 1
	}
	return 0
}

// Check evaluates in against the policy.
func Check(p *Policy, in Input) Decision {
	if p == nil {
		p = &Policy{}
	}
	q := p.defaults()
	d := Decision{Command: in.Command, Verdict: Host}
	if d.Command == "" {
		d.Command = shellJoin(in.Argv)
	}
	if in.InSandbox != nil {
		d.InSandbox = *in.InSandbox
	} else {
		for _, m := range q.InSandboxMarkers {
			if exists(m) {
				d.InSandbox = true
			}
		}
	}
	in.inSandbox = d.InSandbox
	var cmds []SimpleCommand
	if in.Command != "" {
		var err error
		cmds, err = SplitShell(in.Command)
		if err != nil {
			d.Verdict, d.Reason = q.Unparsable, err.Error()
			d.Allowed = allowed(d.Verdict, d.InSandbox)
			return d
		}
	} else if len(in.Argv) > 0 {
		cmds = []SimpleCommand{{Argv: in.Argv}}
	}
	worst := -1
	for _, sc := range cmds {
		segs := q.evalCommand(sc, in, 0)
		for _, s := range segs {
			d.Commands = append(d.Commands, s)
			eff := s.Verdict
			if s.Wrapped && eff == Sandbox {
				eff = Host
			}
			if r := rank(eff); r > worst {
				worst = r
				d.Verdict, d.Reason = eff, s.Reason
			}
		}
	}
	d.Allowed = allowed(d.Verdict, d.InSandbox)
	if d.Verdict == Sandbox && !d.InSandbox {
		d.Hint = q.hint(d.Command, in)
	}
	return d
}

func allowed(verdict string, inSandbox bool) bool {
	switch verdict {
	case Host:
		return true
	case Sandbox:
		return inSandbox
	}
	return false
}

func (q *Policy) hint(command string, in Input) string {
	repo := "<repo>"
	if q.SandboxRoot != "" && in.Cwd != "" {
		root := filepath.Clean(expandHome(q.SandboxRoot, in.Home))
		if rel, err := filepath.Rel(root, filepath.Clean(in.Cwd)); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
			repo = filepath.ToSlash(rel) // oss-run -C is relative to the mount
		}
	}
	h := strings.ReplaceAll(q.SandboxHint, "{repo}", repo)
	return strings.ReplaceAll(h, "{command}", command)
}

var fetchRe = regexp.MustCompile(`\b(curl|wget|fetch|iwr|Invoke-WebRequest)\b`)

// evalCommand evaluates one simple command, unwrapping sudo/env/... and
// shells with -c.
func (q *Policy) evalCommand(sc SimpleCommand, in Input, depth int) []Segment {
	argv := sc.Argv
	seg := Segment{Argv: argv}
	var layers [][]string // outer wrappers, innermost last
	wrapped := false
	for depth < maxDepth {
		layers = append(layers, argv)
		if in.inSandbox {
			wrapped = true
		}
		if q.isSandboxWrapper(argv, in.Home) {
			wrapped = true
			break
		}
		if !in.inSandbox && q.impostorWrapper(argv, in.Home) {
			return []Segment{{Argv: sc.Argv, Program: base(argv[0]), Verdict: Deny,
				Reason: argv[0] + " is named like a sandbox wrapper but is not the configured one"}}
		}
		inner, script, ok := unwrap(argv)
		if script != "" {
			// sh -c SCRIPT / eval / watch "...": parse the script.
			subs, err := SplitShell(script)
			if err != nil {
				return []Segment{{Argv: argv, Program: base(argv[0]), Verdict: q.Unparsable, Reason: err.Error()}}
			}
			var out []Segment
			// the wrapper layers themselves (sudo sh -c ...) still count
			if s, hit := q.matchLayers(layers[:len(layers)-1], in, in.inSandbox); hit {
				out = append(out, s)
			}
			for _, sub := range subs {
				for _, s := range q.evalCommand(sub, in, depth+1) {
					s.Argv = sc.Argv
					out = append(out, s)
				}
			}
			if !in.inSandbox && fetchRe.MatchString(script) && (strings.Contains(script, "$(") || strings.Contains(script, "`")) {
				out = append(out, Segment{Argv: sc.Argv, Program: base(argv[0]), Verdict: q.PipeToShell,
					Reason: "runs a script downloaded at execution time (sh -c \"$(curl ...)\")"})
			}
			return out
		}
		if !ok {
			break
		}
		argv = inner
		depth++
	}
	seg.Program = base(argv[0])
	seg.Wrapped = wrapped

	// Pipe to shell: curl ... | sh, or sh <(curl ...).
	if !wrapped && isShellName(argv[0]) && !hasFlagC(argv) {
		feedsFromFetch := sc.Piped && len(sc.PipedFrom) > 0 && fetchRe.MatchString(strings.Join(sc.PipedFrom, " "))
		procSub := false
		for _, a := range argv[1:] {
			if strings.HasPrefix(a, "<(") && fetchRe.MatchString(a) {
				procSub = true
			}
		}
		if feedsFromFetch || procSub {
			seg.Verdict = q.PipeToShell
			seg.Reason = "pipes a downloaded script into a shell (curl | sh)"
			return []Segment{seg}
		}
		// echo 'go build' | sh: the literal text is the script.
		if sc.Piped && len(sc.PipedFrom) > 1 && readsScript(argv) {
			switch base(sc.PipedFrom[0]) {
			case "echo", "printf":
				var words []string
				for _, w := range sc.PipedFrom[1:] {
					if len(words) == 0 && strings.HasPrefix(w, "-") {
						continue
					}
					words = append(words, w)
				}
				sub, err := SplitShell(strings.Join(words, " "))
				if err != nil {
					return []Segment{{Argv: sc.Argv, Program: seg.Program, Verdict: q.Unparsable,
						Reason: "cannot parse the script piped into " + seg.Program + ": " + err.Error()}}
				}
				out := []Segment{}
				for _, c := range sub {
					out = append(out, q.evalCommand(c, in, depth+1)...)
				}
				if s, hit := q.matchLayers(layers, in, false); hit {
					s.Argv = sc.Argv
					out = append(out, s)
				}
				if len(out) > 0 {
					return out
				}
			}
		}
	}

	if wrapped {
		seg.Verdict = Sandbox
		if s, hit := q.matchEverywhere(argv, 0, in); hit {
			s.Argv, s.Wrapped = sc.Argv, true
			return []Segment{s}
		}
		seg.Reason = "runs through a sandbox wrapper"
		if in.inSandbox {
			seg.Reason = "already inside the sandbox"
		}
		return []Segment{seg}
	}
	if s, hit := q.matchLayers(layers, in, false); hit {
		s.Argv = sc.Argv
		return []Segment{s}
	}
	seg.Verdict = q.Default
	seg.Reason = "no rule matches; default is " + q.Default
	return []Segment{seg}
}

// matchLayers returns the most restrictive explicit rule match over the
// wrapper layers (sudo, env, ...) and the program.
func (q *Policy) matchLayers(layers [][]string, in Input, everywhereOnly bool) (Segment, bool) {
	var best Segment
	hit := false
	for _, l := range layers {
		if i, r := q.match(l, in, everywhereOnly); r != nil {
			if !hit || rank(r.Where) > rank(best.Verdict) {
				best = Segment{Program: base(l[0]), Verdict: r.Where, Rule: i + 1, Reason: ruleReason(r, l)}
				hit = true
			}
		}
	}
	return best, hit
}

// matchEverywhere checks rules marked everywhere against every position
// of a wrapped argv (the wrapper's own options are not parsed).
func (q *Policy) matchEverywhere(argv []string, start int, in Input) (Segment, bool) {
	for k := start; k < len(argv); k++ {
		if i, r := q.match(argv[k:], in, true); r != nil {
			return Segment{Program: base(argv[k]), Verdict: r.Where, Rule: i + 1, Reason: ruleReason(r, argv[k:])}, true
		}
	}
	return Segment{}, false
}

func ruleReason(r *Rule, argv []string) string {
	if r.Reason != "" {
		return r.Reason
	}
	switch r.Where {
	case Host:
		return base(argv[0]) + " is allowed on the host by policy"
	case Sandbox:
		return base(argv[0]) + " runs only in the sandbox by policy"
	}
	return base(argv[0]) + " is denied by policy"
}

func (q *Policy) match(argv []string, in Input, everywhereOnly bool) (int, *Rule) {
	name := argv[0]
	b := base(name)
	args := strings.Join(argv[1:], " ")
	for i := range q.Rules {
		r := &q.Rules[i]
		if everywhereOnly && !r.Everywhere {
			continue
		}
		if !q.cwdOK(r, in) {
			continue
		}
		cmdHit := false
		for _, c := range r.Commands {
			if wildcard(c, b) || (strings.Contains(c, "/") && wildcard(c, name)) {
				cmdHit = true
				break
			}
		}
		if !cmdHit {
			continue
		}
		if len(r.Args) == 0 {
			return i, r
		}
		for _, a := range r.Args {
			if wildcard(a, args) {
				return i, r
			}
		}
	}
	return -1, nil
}

func (q *Policy) cwdOK(r *Rule, in Input) bool {
	if len(r.Cwd) == 0 {
		return true
	}
	cwd := filepath.Clean(in.Cwd)
	for _, d := range r.Cwd {
		d = filepath.Clean(expandHome(d, in.Home))
		if cwd == d || strings.HasPrefix(cwd, d+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// isSandboxWrapper reports whether argv starts with a sandbox wrapper.
// A bare wrapper name ("oss-run") matches only a bare argv[0] (resolved
// via PATH), a wrapper path only the same path; so ./oss-run or
// /tmp/x/oss-run never count. Later wrapper words must follow in order,
// separated only by options and their values ("docker exec -it -w /work
// oss-sandbox ..."), and something must follow the wrapper.
func (q *Policy) isSandboxWrapper(argv []string, home string) bool {
	for _, w := range q.SandboxWrappers {
		ws := strings.Fields(w)
		if strings.ContainsAny(ws[0], `/\`) || strings.HasPrefix(ws[0], "~") {
			if filepath.Clean(expandHome(argv[0], home)) != filepath.Clean(expandHome(ws[0], home)) {
				continue
			}
		} else if argv[0] != ws[0] {
			continue
		}
		k, i := 1, 1
		for ; i < len(argv) && k < len(ws); i++ {
			a := argv[i]
			switch {
			case a == ws[k]:
				k++
			case strings.HasPrefix(a, "-"):
			case strings.HasPrefix(argv[i-1], "-") && !strings.Contains(argv[i-1], "="):
				// value of the previous option
			default:
				i = len(argv) // a different subcommand: not this wrapper
			}
		}
		if k == len(ws) && i < len(argv) {
			return true
		}
	}
	return false
}

// impostorWrapper reports a path whose base name equals a configured
// wrapper (./oss-run, /tmp/x/oss-run) but that is not that wrapper.
func (q *Policy) impostorWrapper(argv []string, home string) bool {
	if !strings.ContainsAny(argv[0], `/\`) && !strings.HasPrefix(argv[0], "~") {
		return false
	}
	b := base(argv[0])
	for _, w := range q.SandboxWrappers {
		if base(strings.Fields(w)[0]) == b {
			return !q.isSandboxWrapper(argv, home)
		}
	}
	return false
}

func base(s string) string {
	if i := strings.LastIndexAny(s, `/\`); i >= 0 {
		return s[i+1:]
	}
	return s
}

var shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "mksh": true, "ash": true, "busybox": false, "fish": true}

func isShellName(s string) bool { return shells[base(s)] }

// hasFlagC reports a -c option (also combined, e.g. -lc, -ec).
func hasFlagC(argv []string) bool {
	_, ok := shellScript(argv)
	return ok
}

// shellScript returns the script of `sh [-opts] -c SCRIPT [args]`.
func shellScript(argv []string) (string, bool) {
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if a == "--" || !strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "+") {
			return "", false
		}
		if a == "-o" || a == "+o" || a == "-O" || a == "+O" || a == "--rcfile" || a == "--init-file" {
			i++
			continue
		}
		if !strings.HasPrefix(a, "--") && strings.Contains(a, "c") {
			if i+1 < len(argv) {
				return argv[i+1], true
			}
			return "", true
		}
	}
	return "", false
}

// unwrap strips one wrapper (sudo, env, nice, timeout, xargs, ...). It
// returns the inner argv, or a script to parse (sh -c, eval, watch).
func unwrap(argv []string) (inner []string, script string, ok bool) {
	b := base(argv[0])
	rest := argv[1:]
	skipOpts := func(withArg string, noArgPrefix bool) []string {
		for len(rest) > 0 {
			a := rest[0]
			if a == "--" {
				return rest[1:]
			}
			if !strings.HasPrefix(a, "-") || a == "-" {
				return rest
			}
			if len(a) == 2 && strings.ContainsRune(withArg, rune(a[1])) {
				if len(rest) < 2 {
					return nil
				}
				rest = rest[2:]
				continue
			}
			if strings.HasPrefix(a, "--") && !strings.Contains(a, "=") && noArgPrefix {
				rest = rest[1:]
				continue
			}
			rest = rest[1:]
		}
		return rest
	}
	switch b {
	case "sudo", "doas", "pkexec", "run0":
		inner = skipOpts("ugCDhprtUTRg", true)
	case "env":
		inner = skipOpts("uCS", true)
		for len(inner) > 0 && isAssignment(inner[0]) {
			inner = inner[1:]
		}
		for i := 1; i < len(argv); i++ { // env -S "cmd args"
			if (argv[i] == "-S" || argv[i] == "--split-string") && i+1 < len(argv) {
				return nil, argv[i+1], true
			}
		}
	case "nice", "ionice", "chrt", "taskset", "stdbuf", "setsid", "nohup", "time", "command", "builtin", "exec",
		"unbuffer", "chronic", "caffeinate", "systemd-inhibit", "firejail", "proxychains", "proxychains4", "torsocks":
		if b == "command" && len(rest) > 0 && (rest[0] == "-v" || rest[0] == "-V") {
			return nil, "", false // lookup only
		}
		inner = skipOpts("ncpaioe", false)
		if b == "chrt" || b == "taskset" {
			if len(inner) > 0 {
				inner = inner[1:] // priority / mask
			}
		}
	case "timeout":
		inner = skipOpts("sk", false)
		if len(inner) > 0 {
			inner = inner[1:] // duration
		}
	case "xargs":
		inner = skipOpts("nILPdsEa", false)
	case "flock":
		for i := 1; i < len(argv); i++ {
			if (argv[i] == "-c" || argv[i] == "--command") && i+1 < len(argv) {
				return nil, argv[i+1], true
			}
		}
		inner = skipOpts("wE", false)
		if len(inner) > 0 {
			inner = inner[1:] // lock file
		}
	case "watch":
		inner = skipOpts("nd", false)
		if len(inner) == 1 {
			return nil, inner[0], true
		}
	case "eval":
		return nil, strings.Join(rest, " "), true
	default:
		if isShellName(b) {
			if s, ok := shellScript(argv); ok {
				return nil, s, true
			}
		}
		return nil, "", false
	}
	if len(inner) == 0 {
		return nil, "", false
	}
	return inner, "", true
}

// shellJoin quotes argv for display.
func shellJoin(argv []string) string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if a != "" && strings.Trim(a, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./=:@%+,") == "" {
			out[i] = a
		} else {
			out[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
	}
	return strings.Join(out, " ")
}
