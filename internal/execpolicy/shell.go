package execpolicy

import (
	"errors"
	"fmt"
	"strings"
)

// SimpleCommand is one command of a shell line, after removing
// redirections, variable assignments and shell keywords.
type SimpleCommand struct {
	Argv []string
	// Piped is true when the command reads the previous pipeline stage.
	Piped bool
	// PipedFrom is the previous stage (when Piped).
	PipedFrom []string
	// Nested is true for commands found in $(...), `...` or <(...).
	Nested bool
}

// ErrUnparsable is returned for input the splitter cannot follow safely.
var ErrUnparsable = errors.New("cannot parse shell command")

const maxDepth = 8

// SplitShell splits a POSIX/bash command line into simple commands. It is
// conservative: quotes, escapes, command and process substitution,
// heredocs, subshells, pipelines and && / || / ; lists are understood;
// variable values are not expanded.
func SplitShell(s string) ([]SimpleCommand, error) {
	return splitShell(s, 0)
}

type lexer struct {
	s     string
	i     int
	depth int
	out   []SimpleCommand
	// current command
	words   []string
	word    strings.Builder
	inWord  bool
	piped   bool
	prev    []string
	redir   bool // next word is a redirection target
	heredoc []heredoc
}

type heredoc struct {
	delim  string
	quoted bool // body is literal (no substitutions)
	owner  int  // index the owning command will get in out
}

func splitShell(s string, depth int) ([]SimpleCommand, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("%w: nesting deeper than %d", ErrUnparsable, maxDepth)
	}
	lx := &lexer{s: s, depth: depth}
	if err := lx.run(); err != nil {
		return nil, err
	}
	return lx.out, nil
}

func (lx *lexer) endWord() {
	if !lx.inWord {
		return
	}
	w := lx.word.String()
	lx.word.Reset()
	lx.inWord = false
	if lx.redir {
		lx.redir = false
		return
	}
	lx.words = append(lx.words, w)
}

// endCommand finishes the current simple command; pipe reports whether
// the next one reads its output.
func (lx *lexer) endCommand(pipe bool) {
	lx.endWord()
	argv := cleanArgv(lx.words)
	if len(argv) > 0 {
		lx.out = append(lx.out, SimpleCommand{Argv: argv, Piped: lx.piped, PipedFrom: lx.prev})
	}
	lx.words = nil
	if pipe {
		lx.piped, lx.prev = true, argv
	} else {
		lx.piped, lx.prev = false, nil
	}
}

func (lx *lexer) nested(inner string) error {
	cmds, err := splitShell(inner, lx.depth+1)
	if err != nil {
		return err
	}
	for _, c := range cmds {
		c.Nested = true
		lx.out = append(lx.out, c)
	}
	return nil
}

func (lx *lexer) run() error {
	s := lx.s
	for lx.i < len(s) {
		c := s[lx.i]
		switch {
		case c == '\\':
			if lx.i+1 < len(s) {
				if s[lx.i+1] != '\n' {
					lx.word.WriteByte(s[lx.i+1])
					lx.inWord = true
				}
				lx.i += 2
				continue
			}
			lx.i++
		case c == '\'':
			j := strings.IndexByte(s[lx.i+1:], '\'')
			if j < 0 {
				return fmt.Errorf("%w: unterminated single quote", ErrUnparsable)
			}
			lx.word.WriteString(s[lx.i+1 : lx.i+1+j])
			lx.inWord = true
			lx.i += j + 2
		case c == '"':
			if err := lx.doubleQuoted(); err != nil {
				return err
			}
		case c == '`':
			j := strings.IndexByte(s[lx.i+1:], '`')
			if j < 0 {
				return fmt.Errorf("%w: unterminated backquote", ErrUnparsable)
			}
			inner := s[lx.i+1 : lx.i+1+j]
			if err := lx.nested(inner); err != nil {
				return err
			}
			lx.word.WriteString("`" + inner + "`")
			lx.inWord = true
			lx.i += j + 2
		case c == '$' && lx.i+1 < len(s) && s[lx.i+1] == '(':
			if err := lx.substitution(lx.i+1, "$"); err != nil {
				return err
			}
		case (c == '<' || c == '>') && lx.i+1 < len(s) && s[lx.i+1] == '(':
			// process substitution <(...) / >(...)
			lx.endWord()
			if err := lx.substitution(lx.i+1, string(c)); err != nil {
				return err
			}
			lx.endWord()
		case c == '#' && !lx.inWord:
			j := strings.IndexByte(s[lx.i:], '\n')
			if j < 0 {
				lx.i = len(s)
			} else {
				lx.i += j
			}
		case c == ' ' || c == '\t':
			lx.endWord()
			lx.i++
		case c == '\n':
			lx.endCommand(false)
			lx.i++
			if err := lx.skipHeredocs(); err != nil {
				return err
			}
		case c == ';' || c == '(' || c == ')' || c == '{' && !lx.inWord && lx.isBraceWord() || c == '}' && !lx.inWord && lx.isBraceWord():
			lx.endCommand(false)
			lx.i++
			if c == ';' && lx.i < len(s) && s[lx.i] == ';' {
				lx.i++
			}
		case c == '&':
			if lx.i+1 < len(s) && s[lx.i+1] == '>' { // &> / &>>
				lx.redirect()
				continue
			}
			lx.endCommand(false)
			lx.i++
			if lx.i < len(s) && s[lx.i] == '&' {
				lx.i++
			}
		case c == '|':
			if lx.i+1 < len(s) && s[lx.i+1] == '|' {
				lx.endCommand(false)
				lx.i += 2
				continue
			}
			lx.endCommand(true)
			lx.i++
			if lx.i < len(s) && s[lx.i] == '&' {
				lx.i++
			}
		case c == '<' || c == '>':
			lx.redirect()
		default:
			lx.word.WriteByte(c)
			lx.inWord = true
			lx.i++
		}
	}
	lx.endCommand(false)
	if len(lx.heredoc) > 0 {
		return fmt.Errorf("%w: unterminated heredoc %q", ErrUnparsable, lx.heredoc[0].delim)
	}
	return nil
}

// isBraceWord: "{" / "}" are only grouping keywords as separate words.
func (lx *lexer) isBraceWord() bool {
	n := lx.i + 1
	return n >= len(lx.s) || strings.IndexByte(" \t\n;", lx.s[n]) >= 0
}

func (lx *lexer) doubleQuoted() error {
	s := lx.s
	lx.i++
	lx.inWord = true
	for lx.i < len(s) {
		c := s[lx.i]
		switch {
		case c == '"':
			lx.i++
			return nil
		case c == '\\' && lx.i+1 < len(s) && strings.IndexByte("$`\"\\\n", s[lx.i+1]) >= 0:
			if s[lx.i+1] != '\n' {
				lx.word.WriteByte(s[lx.i+1])
			}
			lx.i += 2
		case c == '$' && lx.i+1 < len(s) && s[lx.i+1] == '(':
			if err := lx.substitution(lx.i+1, "$"); err != nil {
				return err
			}
		case c == '`':
			j := strings.IndexByte(s[lx.i+1:], '`')
			if j < 0 {
				return fmt.Errorf("%w: unterminated backquote", ErrUnparsable)
			}
			inner := s[lx.i+1 : lx.i+1+j]
			if err := lx.nested(inner); err != nil {
				return err
			}
			lx.word.WriteString("`" + inner + "`")
			lx.i += j + 2
		default:
			lx.word.WriteByte(c)
			lx.i++
		}
	}
	return fmt.Errorf("%w: unterminated double quote", ErrUnparsable)
}

// substitution handles $(...), $((...)), <(...) starting at the "(".
func (lx *lexer) substitution(open int, prefix string) error {
	s := lx.s
	arith := prefix == "$" && open+1 < len(s) && s[open+1] == '('
	end, err := matchParen(s, open)
	if err != nil {
		return err
	}
	inner := s[open+1 : end]
	if !arith {
		if err := lx.nested(inner); err != nil {
			return err
		}
	}
	lx.word.WriteString(prefix + "(" + inner + ")")
	lx.inWord = true
	lx.i = end + 1
	return nil
}

// matchParen finds the ")" matching s[open] == "(", honoring quotes.
func matchParen(s string, open int) (int, error) {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return 0, fmt.Errorf("%w: unterminated single quote", ErrUnparsable)
			}
			i += j + 1
		case '"':
			for i++; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' {
					i++
				}
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i, nil
			}
		}
	}
	return 0, fmt.Errorf("%w: unbalanced parenthesis", ErrUnparsable)
}

// redirect consumes a redirection operator; its target word is dropped.
func (lx *lexer) redirect() {
	s := lx.s
	// a pure-digit word right before is the fd number (2>&1)
	if lx.inWord {
		w := lx.word.String()
		if strings.Trim(w, "0123456789") == "" {
			lx.word.Reset()
			lx.inWord = false
		} else {
			lx.endWord()
		}
	}
	start := lx.i
	for lx.i < len(s) && strings.IndexByte("<>&|-", s[lx.i]) >= 0 {
		lx.i++
	}
	op := s[start:lx.i]
	// "<<<" here-string, "<<" / "<<-" heredoc, ">&2" fd duplication
	for lx.i < len(s) && (s[lx.i] == ' ' || s[lx.i] == '\t') {
		lx.i++
	}
	if strings.HasSuffix(op, "&") && lx.i < len(s) && (isDigitByte(s[lx.i]) || s[lx.i] == '-') {
		for lx.i < len(s) && (isDigitByte(s[lx.i]) || s[lx.i] == '-') {
			lx.i++
		}
		return
	}
	if (op == "<<" || op == "<<-") && lx.i < len(s) {
		j := lx.i
		for j < len(s) && strings.IndexByte(" \t\n;&|<>()", s[j]) < 0 {
			j++
		}
		raw := s[lx.i:j]
		delim := strings.Trim(raw, `'"\`)
		lx.heredoc = append(lx.heredoc, heredoc{delim: delim, quoted: delim != raw, owner: len(lx.out)})
		lx.i = j
		return
	}
	lx.redir = true
}

// skipHeredocs consumes heredoc bodies after a newline. A body fed to a
// shell is parsed as commands; an unquoted body is searched for $(...)
// and `...` substitutions, which the shell would run.
func (lx *lexer) skipHeredocs() error {
	for len(lx.heredoc) > 0 {
		h := lx.heredoc[0]
		found := false
		var body strings.Builder
		for lx.i < len(lx.s) {
			j := strings.IndexByte(lx.s[lx.i:], '\n')
			var line string
			if j < 0 {
				line = lx.s[lx.i:]
				lx.i = len(lx.s)
			} else {
				line = lx.s[lx.i : lx.i+j]
				lx.i += j + 1
			}
			if strings.TrimLeft(line, "\t") == h.delim {
				found = true
				break
			}
			body.WriteString(line)
			body.WriteByte('\n')
		}
		if !found {
			return fmt.Errorf("%w: unterminated heredoc %q", ErrUnparsable, h.delim)
		}
		lx.heredoc = lx.heredoc[1:]
		if h.owner < len(lx.out) && (readsScript(lx.out[h.owner].Argv) || lx.feedsShell(h.owner)) {
			if err := lx.nested(body.String()); err != nil {
				return err
			}
		} else if !h.quoted {
			if err := lx.substitutionsIn(body.String()); err != nil {
				return err
			}
		}
	}
	return nil
}

// readsScript reports whether argv is a shell reading commands from stdin.
func readsScript(argv []string) bool {
	if len(argv) == 0 || !isShellName(argv[0]) || hasFlagC(argv) {
		return false
	}
	for _, a := range argv[1:] {
		if !strings.HasPrefix(a, "-") || a == "-" {
			return a == "-"
		}
	}
	return true
}

// feedsShell reports whether the output of command i is piped into a
// shell reading stdin (cat <<EOF | bash).
func (lx *lexer) feedsShell(i int) bool {
	for k := i + 1; k < len(lx.out); k++ {
		if lx.out[k].Nested {
			continue
		}
		return lx.out[k].Piped && readsScript(lx.out[k].Argv)
	}
	return false
}

// substitutionsIn parses the $(...) and `...` parts of text.
func (lx *lexer) substitutionsIn(text string) error {
	for i := 0; i < len(text); i++ {
		switch {
		case text[i] == '\\':
			i++
		case text[i] == '$' && i+1 < len(text) && text[i+1] == '(':
			end, err := matchParen(text, i+1)
			if err != nil {
				return err
			}
			if !(i+2 < len(text) && text[i+2] == '(') {
				if err := lx.nested(text[i+2 : end]); err != nil {
					return err
				}
			}
			i = end
		case text[i] == '`':
			j := strings.IndexByte(text[i+1:], '`')
			if j < 0 {
				return fmt.Errorf("%w: unterminated backquote", ErrUnparsable)
			}
			if err := lx.nested(text[i+1 : i+1+j]); err != nil {
				return err
			}
			i += j + 1
		}
	}
	return nil
}

func isDigitByte(c byte) bool { return c >= '0' && c <= '9' }

var keywords = map[string]bool{
	"if": true, "then": true, "else": true, "elif": true, "fi": true,
	"do": true, "done": true, "while": true, "until": true, "esac": true,
	"!": true, "{": true, "}": true, "time": true, "coproc": true,
}

// cleanArgv drops leading keywords and VAR=value assignments; "for",
// "select" and "case" heads are not commands.
func cleanArgv(w []string) []string {
	for len(w) > 0 {
		switch {
		case keywords[w[0]]:
			w = w[1:]
		case w[0] == "for" || w[0] == "select" || w[0] == "case" || w[0] == "function":
			return nil
		case isAssignment(w[0]):
			w = w[1:]
		default:
			if len(w) > 0 && strings.HasSuffix(w[0], ")") && !strings.HasPrefix(w[0], "$(") && !strings.Contains(w[0], "(") {
				return nil // case pattern "foo)"
			}
			return w
		}
	}
	return nil
}

func isAssignment(s string) bool {
	i := strings.IndexByte(s, '=')
	if i <= 0 {
		return false
	}
	name := strings.TrimSuffix(s[:i], "+")
	for k, r := range name {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || k > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return name != ""
}
