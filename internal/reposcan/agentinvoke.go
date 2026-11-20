package reposcan

import (
	"path"
	"strings"
)

// Agent invocation detection for ci.agent-publish-token.
//
// The rule must fire on a job that actually runs an AI coding agent, not on
// a job that merely mentions one: image names (ghcr.io/<org>/openhands),
// npm package names in a publish step (@openai/codex), Co-authored-by
// trailers, comments and echo strings are all false positives seen in the
// November 2026 mass scan. A run script is therefore split into shell
// commands (quote-aware, comments dropped) and only the command word of
// each command, after wrappers like env/sudo/timeout/npx/uvx/python -m, is
// compared with the known agent CLIs.

// agentCLIs maps a command word (basename or npm package) to the agent
// name and whether a subcommand is required (goose run, opencode run).
var agentCLIs = map[string]struct {
	name string
	sub  string // required first argument, "" = any
}{
	"codex":                     {"codex", ""},
	"@openai/codex":             {"codex", ""},
	"claude":                    {"claude", ""},
	"@anthropic-ai/claude-code": {"claude", ""},
	"gemini":                    {"gemini", ""},
	"@google/gemini-cli":        {"gemini", ""},
	"aider":                     {"aider", ""},
	"aider-chat":                {"aider", ""},
	"openhands":                 {"openhands", ""},
	"openhands-ai":              {"openhands", ""},
	"cursor-agent":              {"cursor-agent", ""},
	"goose":                     {"goose", "run"},
	"opencode":                  {"opencode", "run"},
	"opencode-ai":               {"opencode", "run"},
}

// agentSetupArgs are first arguments that configure or inspect a CLI
// without running the agent on any input.
var agentSetupArgs = map[string]bool{
	"--version": true, "-V": true, "-v": true, "version": true, "--help": true, "-h": true, "help": true,
	"login": true, "logout": true, "auth": true, "mcp": true, "config": true, "install": true, "update": true,
	"upgrade": true, "doctor": true, "completion": true, "setup-token": true, "features": true,
}

// agentInvocation returns a short description of the first agent CLI
// invocation in a shell script, or "".
func agentInvocation(script string) string {
	return agentInvocationDepth(script, 0)
}

func agentInvocationDepth(script string, depth int) string {
	if depth > 3 {
		return ""
	}
	script = strings.ReplaceAll(script, "\\\r\n", " ")
	script = strings.ReplaceAll(script, "\\\n", " ")
	for _, cmd := range shellCommands(script) {
		if got := agentCommand(cmd, depth); got != "" {
			return got
		}
	}
	return ""
}

// shellCommands splits a script into simple commands: separators are
// newlines, ; & | && || ( ) $( and backticks outside quotes; # starts a
// comment at a word boundary. Each command is returned as its words with
// quotes removed. Heredoc bodies are not interpreted (they are data).
func shellCommands(script string) [][]string {
	var cmds [][]string
	var words []string
	var cur strings.Builder
	inWord := false
	endWord := func() {
		if inWord {
			words = append(words, cur.String())
			cur.Reset()
			inWord = false
		}
	}
	endCmd := func() {
		endWord()
		if len(words) > 0 {
			cmds = append(cmds, words)
			words = nil
		}
	}
	var heredoc string
	lines := strings.Split(script, "\n")
	for _, line := range lines {
		if heredoc != "" {
			if strings.TrimSpace(line) == heredoc {
				heredoc = ""
			}
			continue
		}
		var q rune // current quote
		rs := []rune(line)
		for i := 0; i < len(rs); i++ {
			r := rs[i]
			if q != 0 {
				if r == q {
					q = 0
					continue
				}
				if q == '"' && r == '\\' && i+1 < len(rs) {
					i++
					cur.WriteRune(rs[i])
					continue
				}
				cur.WriteRune(r)
				continue
			}
			switch {
			case r == '\'' || r == '"':
				q = r
				inWord = true
			case r == '\\' && i+1 < len(rs):
				i++
				cur.WriteRune(rs[i])
				inWord = true
			case r == '#' && !inWord:
				i = len(rs) // comment to end of line
			case r == ' ' || r == '\t' || r == '\r':
				endWord()
			case r == ';' || r == '&' || r == '|' || r == '(' || r == ')' || r == '`':
				endCmd()
			case r == '$' && i+1 < len(rs) && rs[i+1] == '(':
				endCmd()
				i++
			case r == '<' && i+1 < len(rs) && rs[i+1] == '<':
				// heredoc: remember the delimiter, skip the body lines
				j := i + 2
				if j < len(rs) && rs[j] == '-' {
					j++
				}
				for j < len(rs) && (rs[j] == ' ' || rs[j] == '\t') {
					j++
				}
				k := j
				for k < len(rs) && rs[k] != ' ' && rs[k] != '\t' && rs[k] != ';' && rs[k] != '|' && rs[k] != '&' && rs[k] != ')' {
					k++
				}
				heredoc = strings.Trim(string(rs[j:k]), `'"`)
				endWord()
				i = k - 1
			default:
				cur.WriteRune(r)
				inWord = true
			}
		}
		endCmd()
	}
	endCmd()
	return cmds
}

// agentCommand judges one simple command.
func agentCommand(w []string, depth int) string {
	i := 0
	skipFlags := func() {
		for i < len(w) && strings.HasPrefix(w[i], "-") {
			i++
		}
	}
	for i < len(w) {
		word := w[i]
		base := path.Base(word)
		switch {
		case isAssignment(word):
			i++
			continue
		case base == "sudo" || base == "exec" || base == "nohup" || base == "command" || base == "time" || base == "xvfb-run" || base == "stdbuf" || base == "nice":
			i++
			skipFlags()
			continue
		case base == "env":
			i++
			for i < len(w) && (strings.HasPrefix(w[i], "-") || isAssignment(w[i])) {
				i++
			}
			continue
		case base == "timeout":
			i++
			skipFlags()
			if i < len(w) {
				i++ // duration
			}
			continue
		case base == "npx" || base == "bunx" || base == "pnpx" || base == "uvx":
			i++
			for i < len(w) && strings.HasPrefix(w[i], "-") {
				if (w[i] == "-p" || w[i] == "--package" || w[i] == "--from") && i+1 < len(w) {
					i++
				}
				i++
			}
			continue
		case (base == "pnpm" || base == "yarn") && i+1 < len(w) && w[i+1] == "dlx",
			base == "pipx" && i+1 < len(w) && w[i+1] == "run",
			base == "npm" && i+1 < len(w) && w[i+1] == "exec":
			i += 2
			for i < len(w) && strings.HasPrefix(w[i], "-") {
				i++
			}
			continue
		case base == "uv" && i+2 < len(w) && w[i+1] == "tool" && w[i+2] == "run":
			i += 3
			skipFlags()
			continue
		case base == "uv" && i+1 < len(w) && w[i+1] == "run":
			i += 2
			skipFlags()
			continue
		case (base == "bash" || base == "sh" || base == "zsh" || base == "dash") && i+2 < len(w) && strings.HasPrefix(w[i+1], "-") && strings.Contains(w[i+1], "c"):
			return agentInvocationDepth(w[i+2], depth+1)
		case strings.HasPrefix(base, "python") && i+2 < len(w) && w[i+1] == "-m":
			mod := w[i+2]
			if mod == "openhands" || strings.HasPrefix(mod, "openhands.") || mod == "aider" {
				return "python -m " + mod
			}
			return ""
		}
		break
	}
	if i >= len(w) {
		return ""
	}
	name := w[i]
	if strings.HasPrefix(name, "@") {
		// npm package spec: @scope/pkg@version
		if at := strings.LastIndex(name, "@"); at > 0 {
			name = name[:at]
		}
	} else {
		name = path.Base(name)
		if at := strings.Index(name, "@"); at > 0 {
			name = name[:at]
		}
		if at := strings.Index(name, "=="); at > 0 {
			name = name[:at]
		}
	}
	cli, ok := agentCLIs[strings.ToLower(name)]
	if !ok {
		return ""
	}
	arg := ""
	if i+1 < len(w) {
		arg = w[i+1]
	}
	if agentSetupArgs[arg] {
		return ""
	}
	if cli.sub != "" && arg != cli.sub {
		return ""
	}
	out := cli.name
	if arg != "" && !strings.ContainsAny(arg, " \t") && len(arg) < 24 {
		out += " " + arg
	}
	return out
}

func isAssignment(w string) bool {
	eq := strings.IndexByte(w, '=')
	if eq <= 0 {
		return false
	}
	for j, c := range w[:eq] {
		if !(c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || j > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
