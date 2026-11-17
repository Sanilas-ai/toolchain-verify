// Package trace reads an already-running agent's session journal and
// reports unauthorized tool calls. It opens the journal only. Credential
// files are refused. Argument text is not copied into findings. There is
// no model in the verdict: allow and deny are this package's rules plus
// execpolicy.
package trace

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/Sanilas-ai/toolchain-verify/internal/execpolicy"
	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

// Options configure one trace.
type Options struct {
	Policy       *execpolicy.Policy
	Home         string
	Cwd          string
	TrustedRoots []string
	// FollowScript is passed to execpolicy when a shell command names a file.
	FollowScript bool
	// MinSpan is the shortest untrusted-result fragment that can taint a
	// later outbound or write argument (default 24).
	MinSpan int
	// StopOnFinding makes Watch return after the first failing event.
	StopOnFinding bool
}

// Report is the result of scanning a journal.
type Report struct {
	SchemaVersion int                `json:"schema_version"`
	Path          string             `json:"path,omitempty"`
	OK            bool               `json:"ok"`
	Events        int                `json:"events"`
	Findings      []findings.Finding `json:"findings"`
}

type event struct {
	kind  string // call or result
	name  string
	class string
	args  string
	text  string
}

// ErrCredential is returned when the path is a credential file.
var ErrCredential = errors.New("refusing to open a credential file")

// AllowJournal reports whether path may be opened as a session journal.
func AllowJournal(path string) error {
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case "auth.json", "credentials.json", ".credentials.json", "hosts.yml", "id_rsa", "id_ed25519":
		return ErrCredential
	}
	return nil
}

type session struct {
	opt       Options
	rep       *Report
	tainted   []string
	min       int
	lastClass string
}

func newSession(opt Options) *session {
	min := opt.MinSpan
	if min <= 0 {
		min = 24
	}
	return &session{opt: opt, min: min, rep: &Report{SchemaVersion: findings.SchemaVersion, OK: true}}
}

func (s *session) line(line string) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] != '{' {
		return
	}
	for _, ev := range parseLine([]byte(line)) {
		if ev.kind == "result" && ev.class == "" {
			ev.class = s.lastClass
		}
		s.rep.Events++
		s.rep.Findings = append(s.rep.Findings, judge(ev, s.opt, &s.tainted, s.min)...)
		if ev.kind == "call" {
			s.lastClass = ev.class
		}
		if ev.kind == "result" && ev.class == "untrusted" {
			s.tainted = appendSpans(s.tainted, ev.text, s.min)
		}
	}
}

func (s *session) finish() {
	fail, _, _ := findings.Counts(s.rep.Findings)
	s.rep.OK = fail == 0
}

// Scan reads a finished journal.
func Scan(r io.Reader, opt Options) *Report {
	s := newSession(opt)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		s.line(sc.Text())
	}
	s.finish()
	return s.rep
}

// Watch tails path until stop is closed or, when StopOnFinding is set,
// until a failing event is seen. Existing bytes are scanned first.
func Watch(path string, opt Options, stop <-chan struct{}) (*Report, error) {
	if err := AllowJournal(path); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := newSession(opt)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		s.line(sc.Text())
	}
	s.finish()
	s.rep.Path = path
	if opt.StopOnFinding && !s.rep.OK {
		return s.rep, nil
	}
	offset, _ := f.Seek(0, io.SeekCurrent)
	buf := make([]byte, 0, 64<<10)
	for {
		select {
		case <-stop:
			s.finish()
			return s.rep, nil
		case <-time.After(150 * time.Millisecond):
		}
		st, err := f.Stat()
		if err != nil {
			s.finish()
			return s.rep, err
		}
		if st.Size() < offset {
			offset = 0
			buf = buf[:0]
		}
		if st.Size() == offset {
			continue
		}
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			s.finish()
			return s.rep, err
		}
		chunk := make([]byte, st.Size()-offset)
		n, err := io.ReadFull(f, chunk)
		offset += int64(n)
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			s.finish()
			return s.rep, err
		}
		buf = append(buf, chunk[:n]...)
		for {
			i := strings.IndexByte(string(buf), '\n')
			if i < 0 {
				break
			}
			line := string(buf[:i])
			buf = append([]byte(nil), buf[i+1:]...)
			s.line(line)
			if opt.StopOnFinding {
				s.finish()
				if !s.rep.OK {
					return s.rep, nil
				}
			}
		}
	}
}

func judge(ev event, opt Options, tainted *[]string, min int) []findings.Finding {
	if ev.kind != "call" {
		return nil
	}
	var out []findings.Finding
	switch ev.class {
	case "shell":
		if opt.Policy == nil {
			out = append(out, findings.Finding{Rule: "trace.shell", Severity: findings.SevFail, Path: ev.name,
				Message: "shell tool call and no exec policy is loaded"})
			break
		}
		d := execpolicy.Check(opt.Policy, execpolicy.Input{
			Command: ev.args, Cwd: opt.Cwd, Home: opt.Home, FollowScript: opt.FollowScript,
		})
		if !d.Allowed {
			out = append(out, findings.Finding{Rule: "trace.shell", Severity: findings.SevFail, Path: ev.name,
				Message: "shell tool call is not allowed by exec policy (" + d.Verdict + ")"})
		}
	case "path", "write":
		if bad := badPath(ev.args, opt); bad != "" {
			out = append(out, findings.Finding{Rule: "trace.path", Severity: findings.SevFail, Path: ev.name,
				Message: "tool argument names " + bad})
		}
	}
	if ev.class == "outbound" || ev.class == "write" {
		for _, span := range *tainted {
			if len(span) >= min && strings.Contains(ev.args, span) {
				out = append(out, findings.Finding{Rule: "trace.flow", Severity: findings.SevFail, Path: ev.name,
					Message: "untrusted tool result reached an outbound or out-of-repo write argument"})
				break
			}
		}
	}
	return out
}

func badPath(args string, opt Options) string {
	low := strings.ToLower(args)
	for _, frag := range []string{"/.ssh/", "/.gnupg/", "/.aws/", "auth.json", ".credentials.json", "/.config/gh/", "/.kube/"} {
		if strings.Contains(low, frag) {
			return "a credential path"
		}
	}
	if len(opt.TrustedRoots) == 0 {
		return ""
	}
	for _, field := range strings.Fields(args) {
		field = strings.Trim(field, `"'`)
		if field == "" || (!filepath.IsAbs(field) && !strings.HasPrefix(field, "~")) {
			continue
		}
		p := field
		if strings.HasPrefix(p, "~/") && opt.Home != "" {
			p = filepath.Join(opt.Home, p[2:])
		}
		p = filepath.Clean(p)
		inside := false
		for _, root := range opt.TrustedRoots {
			root = filepath.Clean(root)
			if p == root || strings.HasPrefix(p, root+string(filepath.Separator)) {
				inside = true
				break
			}
		}
		if !inside {
			return "a path outside trusted roots"
		}
	}
	return ""
}

func appendSpans(have []string, text string, min int) []string {
	if len(have) >= 64 {
		return have
	}
	field := strings.FieldsFunc(text, unicode.IsSpace)
	for _, f := range field {
		if len(f) < min || len(f) > 200 {
			continue
		}
		if strings.ContainsAny(f, "{}[]()<>") && len(f) < min+8 {
			continue
		}
		have = append(have, f)
		if len(have) >= 64 {
			break
		}
	}
	return have
}

func parseLine(line []byte) []event {
	var doc map[string]json.RawMessage
	if json.Unmarshal(line, &doc) != nil {
		return nil
	}
	if ev := jsonString(doc, "event"); ev == "call" || ev == "result" {
		name := jsonString(doc, "name")
		text := jsonString(doc, "text")
		args := jsonString(doc, "args")
		if args == "" {
			if raw, ok := doc["input"]; ok {
				args = string(raw)
			}
		}
		if text == "" {
			if raw, ok := doc["output"]; ok {
				text = string(raw)
			}
		}
		return []event{{kind: ev, name: name, class: classOf(name), args: args, text: text}}
	}
	msg, ok := doc["message"]
	if !ok {
		return nil
	}
	var message struct {
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(msg, &message) != nil || len(message.Content) == 0 || message.Content[0] != '[' {
		return nil
	}
	var blocks []struct {
		Type    string          `json:"type"`
		Name    string          `json:"name"`
		Input   json.RawMessage `json:"input"`
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(message.Content, &blocks) != nil {
		return nil
	}
	var out []event
	for _, b := range blocks {
		switch b.Type {
		case "tool_use":
			args := toolArgs(b.Name, b.Input)
			out = append(out, event{kind: "call", name: b.Name, class: classOf(b.Name), args: args})
		case "tool_result":
			text := contentText(b.Content)
			out = append(out, event{kind: "result", name: "tool_result", text: text})
		}
	}
	return out
}

func toolArgs(name string, input json.RawMessage) string {
	if len(input) == 0 {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(input, &m) != nil {
		return string(input)
	}
	if classOf(name) == "shell" {
		if c, ok := m["command"].(string); ok {
			return c
		}
		if c, ok := m["cmd"].(string); ok {
			return c
		}
	}
	return string(input)
}

func contentText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var blocks []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &blocks) == nil {
		var b strings.Builder
		for _, bl := range blocks {
			b.WriteString(bl.Text)
			b.WriteByte('\n')
		}
		return b.String()
	}
	return string(raw)
}

func jsonString(doc map[string]json.RawMessage, key string) string {
	raw, ok := doc[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}

func classOf(name string) string {
	n := strings.ToLower(name)
	switch {
	case n == "bash" || n == "shell" || strings.Contains(n, "shell") || n == "exec" || n == "powershell" || strings.Contains(n, "run_command"):
		return "shell"
	case strings.Contains(n, "webfetch") || strings.Contains(n, "web_search") || strings.Contains(n, "websearch") || n == "fetch" || strings.Contains(n, "http") || strings.Contains(n, "browser"):
		return "untrusted"
	case strings.Contains(n, "send") || strings.Contains(n, "post") || strings.Contains(n, "comment") || strings.Contains(n, "email") || strings.Contains(n, "slack"):
		return "outbound"
	case strings.Contains(n, "write") || strings.Contains(n, "edit") || strings.Contains(n, "delete") || strings.Contains(n, "apply_patch"):
		return "write"
	case strings.Contains(n, "read") || strings.Contains(n, "grep") || strings.Contains(n, "glob"):
		return "path"
	default:
		return "other"
	}
}
