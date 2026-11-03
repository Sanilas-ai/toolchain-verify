package execlint

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Sanilas-ai/toolchain-verify/internal/agent"
	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

// Options carry command-line overrides and environment facts.
type Options struct {
	Home, Cwd   string
	ManifestDir string
	// Paths override Policy.Paths when non-empty.
	Paths []string
	// Fail forces ModeFail.
	Fail bool
	// Strict makes warnings fail.
	Strict bool
	// ExtraWrappers add to Policy.Wrappers.
	ExtraWrappers []string
	// MaxFiles caps the number of source files read (default 50000).
	MaxFiles int
	// MaxFileSize skips larger files (default 1 MiB).
	MaxFileSize int64
}

// Report is the result of a lint run.
type Report struct {
	Roots     []string           `json:"roots"`
	Mode      string             `json:"mode"`
	Strict    bool               `json:"strict"`
	OK        bool               `json:"ok"`
	Files     int                `json:"files_scanned"`
	LLMFiles  int                `json:"llm_files"`
	Sinks     int                `json:"exec_sinks"`
	Truncated bool               `json:"truncated,omitempty"`
	Findings  []findings.Finding `json:"findings"`
	Ignored   int                `json:"ignored,omitempty"`
}

// Counts returns the number of findings per severity.
func (r *Report) Counts() (fail, warn, info int) { return findings.Counts(r.Findings) }

// Hardened is the container invocation the linter accepts as isolation.
const Hardened = "docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 --pids-limit 128 --memory 512m --tmpfs /tmp:rw,noexec,nosuid,size=64m IMAGE@sha256:... CMD"

const fixText = "run it through a hardened container (" + Hardened + "), e.g. examples/sandbox/run-isolated.sh or the Go helper package sandbox; after review, mark a deliberate call with a `toolchain-verify:sandboxed` comment"

var skipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, "node_modules": true, "vendor": true,
	".venv": true, "venv": true, "site-packages": true, "dist": true, "build": true,
	"__pycache__": true, ".tox": true, ".mypy_cache": true, ".pytest_cache": true,
	"target": true, ".next": true, ".cache": true, "testdata": true, "__tests__": true,
	"third_party": true, ".idea": true, ".vscode": true,
}

type lang int

const (
	langNone lang = iota
	langGo
	langPy
	langJS
	langSh
)

func langOf(name string) lang {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".go":
		return langGo
	case ".py":
		return langPy
	case ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts":
		return langJS
	case ".sh", ".bash":
		return langSh
	}
	return langNone
}

func isTestFile(name string) bool {
	n := strings.ToLower(name)
	switch {
	case strings.HasSuffix(n, "_test.go"),
		strings.HasPrefix(n, "test_") && strings.HasSuffix(n, ".py"),
		strings.HasSuffix(n, "_test.py"), n == "conftest.py",
		strings.Contains(n, ".test."), strings.Contains(n, ".spec."):
		return true
	}
	return false
}

// Run lints the configured paths. It reads files only; nothing is executed.
func Run(p *Policy, opt Options) (*Report, error) {
	if p == nil {
		p = &Policy{}
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	home := filepath.Clean(opt.Home)
	base := opt.ManifestDir
	if base == "" {
		base = opt.Cwd
	}
	var roots []string
	if len(opt.Paths) > 0 {
		for _, r := range opt.Paths {
			roots = append(roots, expand(r, home, opt.Cwd))
		}
	} else {
		for _, r := range p.Paths {
			roots = append(roots, expand(r, home, base))
		}
	}
	if len(roots) == 0 {
		roots = []string{filepath.Clean(opt.Cwd)}
	}
	cred := agent.CredentialDirs(home)
	for _, r := range roots {
		if r == "/" || r == home {
			return nil, fmt.Errorf("%w: %s is too broad to lint; name project directories", agent.ErrRefused, r)
		}
		for _, d := range cred {
			if r == d || strings.HasPrefix(r, d+string(filepath.Separator)) {
				return nil, fmt.Errorf("%w: %s is a credential location", agent.ErrRefused, r)
			}
		}
	}
	mode := p.Mode
	if mode == "" {
		mode = ModeReport
	}
	if opt.Fail {
		mode = ModeFail
	}
	l := &linter{
		policy:   p,
		mode:     mode,
		wrappers: append(append(append([]string(nil), DefaultWrappers...), p.Wrappers...), opt.ExtraWrappers...),
		markers:  p.ExtraLLMMarkers,
		maxFiles: opt.MaxFiles,
		maxSize:  opt.MaxFileSize,
		depth:    p.MaxDepth,
		cred:     cred,
		exclude:  p.Exclude,
		base:     base,
		home:     home,
		c:        &findings.Collector{Ignore: p.Ignore},
		rep:      &Report{Roots: roots, Mode: mode, Strict: opt.Strict || p.Strict},
	}
	if l.maxFiles <= 0 {
		l.maxFiles = 50000
	}
	if l.maxSize <= 0 {
		l.maxSize = 1 << 20
	}
	if l.depth == 0 {
		l.depth = 12
	}
	for _, r := range roots {
		l.walk(r)
	}
	l.rep.Findings = l.c.Sorted()
	l.rep.Ignored = l.c.Ignored
	l.rep.OK = findings.OK(l.rep.Findings, l.rep.Strict)
	return l.rep, nil
}

type linter struct {
	policy   *Policy
	mode     string
	wrappers []string
	markers  []string
	maxFiles int
	maxSize  int64
	depth    int
	cred     []string
	exclude  []string
	base     string
	home     string
	c        *findings.Collector
	rep      *Report
}

func (l *linter) excluded(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	rel = filepath.ToSlash(rel)
	abs := filepath.ToSlash(path)
	name := filepath.Base(path)
	for _, ex := range l.exclude {
		ex = filepath.ToSlash(ex)
		if !strings.Contains(ex, "/") {
			if ok, _ := filepath.Match(ex, name); ok {
				return true
			}
			continue
		}
		re := globRegexp(ex)
		if re.MatchString(rel) {
			return true
		}
		if strings.HasPrefix(ex, "/") || strings.HasPrefix(ex, "~/") {
			if globRegexp(filepath.ToSlash(expand(ex, l.home, l.base))).MatchString(abs) {
				return true
			}
		}
	}
	return false
}

// globRegexp compiles a slash glob where "**" spans directories and a
// trailing "/**" also matches the directory itself.
func globRegexp(g string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(g); i++ {
		switch c := g[i]; {
		case strings.HasPrefix(g[i:], "**/"):
			b.WriteString("(?:.*/)?")
			i += 2
		case strings.HasPrefix(g[i:], "/**") && i+3 == len(g):
			b.WriteString("(?:/.*)?")
			i += 2
		case strings.HasPrefix(g[i:], "**"):
			b.WriteString(".*")
			i++
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return regexp.MustCompile(`^\x00$`)
	}
	return re
}

func (l *linter) walk(root string) {
	st, err := os.Lstat(root)
	if err != nil {
		l.c.Add(findings.Finding{Rule: "exec.path-missing", Severity: findings.SevWarn, Path: root, Message: "path to lint does not exist or is not readable"})
		return
	}
	if !st.IsDir() {
		if st.Mode().IsRegular() {
			l.file(root, st.Size())
		}
		return
	}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if l.rep.Files >= l.maxFiles {
			l.rep.Truncated = true
			return filepath.SkipAll
		}
		if d.IsDir() {
			if p == root {
				return nil
			}
			if skipDirs[d.Name()] || l.excluded(p, root) {
				return filepath.SkipDir
			}
			for _, c := range l.cred {
				if p == c || strings.HasPrefix(p, c+string(filepath.Separator)) {
					return filepath.SkipDir
				}
			}
			rel, _ := filepath.Rel(root, p)
			if strings.Count(rel, string(filepath.Separator))+1 > l.depth {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || langOf(d.Name()) == langNone {
			return nil
		}
		if !l.policy.IncludeTests && isTestFile(d.Name()) {
			return nil
		}
		if l.excluded(p, root) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		l.file(p, info.Size())
		return nil
	})
}

func (l *linter) file(path string, size int64) {
	lg := langOf(path)
	if lg == langNone || size > l.maxSize {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil || bytes.IndexByte(data, 0) >= 0 {
		return
	}
	l.rep.Files++
	for _, f := range analyze(path, lg, string(data), l.wrappers, l.markers, l.sev(), l.rep) {
		l.c.Add(f)
	}
}

func (l *linter) sev() string {
	if l.mode == ModeFail {
		return findings.SevFail
	}
	return findings.SevWarn
}

// --- analysis --------------------------------------------------------------

type sinkPat struct {
	kw   []string // literal prefilter: the line must contain one of these
	re   *regexp.Regexp
	kind string   // process, shell, code
	need []string // the file must contain one of these literals
}

var (
	goExecImport = []string{`"os/exec"`}
	jsChild      = []string{"child_process", "execa", "Bun.spawn", "Deno.Command", `"zx"`, "'zx'"}
)

var sinks = map[lang][]sinkPat{
	langGo: {
		{kw: []string{"exec.Command"}, re: regexp.MustCompile(`\bexec\.Command(Context)?\s*\(`), kind: "process", need: goExecImport},
		{kw: []string{"syscall."}, re: regexp.MustCompile(`\bsyscall\.(Exec|ForkExec)\s*\(`), kind: "process"},
		{kw: []string{"os.StartProcess"}, re: regexp.MustCompile(`\bos\.StartProcess\s*\(`), kind: "process"},
	},
	langPy: {
		{kw: []string{"subprocess."}, re: regexp.MustCompile(`\bsubprocess\.(run|call|check_call|check_output|Popen|getoutput|getstatusoutput)\s*\(`), kind: "process"},
		{kw: []string{"os.system", "os.popen"}, re: regexp.MustCompile(`\bos\.(system|popen)\s*\(`), kind: "shell"},
		{kw: []string{"os.exec", "os.spawn", "os.posix_spawn"}, re: regexp.MustCompile(`\bos\.(exec[lv]p?e?|spawn[lv]p?e?|posix_spawnp?)\s*\(`), kind: "process"},
		{kw: []string{"pty.spawn"}, re: regexp.MustCompile(`\bpty\.spawn\s*\(`), kind: "process"},
		{kw: []string{"create_subprocess_exec"}, re: regexp.MustCompile(`\basyncio\.create_subprocess_exec\s*\(`), kind: "process"},
		{kw: []string{"create_subprocess_shell"}, re: regexp.MustCompile(`\basyncio\.create_subprocess_shell\s*\(`), kind: "shell"},
		{kw: []string{"exec(", "eval(", "exec (", "eval ("}, re: regexp.MustCompile(`(^|[^\w.])(exec|eval)\s*\(`), kind: "code"},
	},
	langJS: {
		{kw: []string{"exec(", "execSync(", "exec (", "execSync ("}, re: regexp.MustCompile(`(^|[^\w.])(exec|execSync)\s*\(|\b(child_process|cp|childProcess)\.(exec|execSync)\s*\(`), kind: "shell", need: jsChild},
		{kw: []string{"execFile", "spawn", "fork"}, re: regexp.MustCompile(`(^|[^\w.])(execFile|execFileSync|spawn|spawnSync|fork)\s*\(|\.(execFile|execFileSync|spawn|spawnSync)\s*\(`), kind: "process", need: jsChild},
		{kw: []string{"execa"}, re: regexp.MustCompile(`\bexeca(Sync|Command|CommandSync)?\s*\(`), kind: "process"},
		{kw: []string{"Bun.spawn", "Deno.Command"}, re: regexp.MustCompile(`\bBun\.spawn(Sync)?\s*\(|\bnew\s+Deno\.Command\s*\(`), kind: "process"},
		{kw: []string{"eval", "Function", "vm."}, re: regexp.MustCompile(`(^|[^\w.])eval\s*\(|\bnew\s+Function\s*\(|\bvm\.(runInNewContext|runInThisContext|runInContext|Script)\b`), kind: "code"},
	},
	langSh: {
		{kw: []string{"eval"}, re: regexp.MustCompile(`(^|[\s;&|(])eval\s+["']?\$`), kind: "code"},
		{kw: []string{"sh -c"}, re: regexp.MustCompile(`\b(ba|z|da)?sh\s+-c\s+["']?\$`), kind: "shell"},
	},
}

var (
	reStrongPy  = regexp.MustCompile(`(?m)^\s*(import|from)\s+(openai|anthropic|litellm|ollama|langchain[\w.]*|langgraph[\w.]*|llama_index[\w.]*|google\.generativeai|google\.genai|mistralai|groq|cohere|transformers|vllm|crewai|autogen[\w.]*|praisonai[\w.]*|smolagents|pydantic_ai|instructor|dspy|mcp)\b`)
	reStrongJS  = regexp.MustCompile(`(require\(\s*|from\s+|import\s+)["'](openai|@anthropic-ai/sdk|@google/generative-ai|@google/genai|ollama|langchain|@langchain/[\w-]+|ai|@ai-sdk/[\w-]+|@modelcontextprotocol/sdk[\w/.-]*|groq-sdk|@mistralai/mistralai|llamaindex|@openai/agents)["']`)
	reStrongGo  = regexp.MustCompile(`"(github\.com/sashabaranov/go-openai|github\.com/openai/openai-go[\w/.-]*|github\.com/anthropics/anthropic-sdk-go[\w/.-]*|github\.com/tmc/langchaingo[\w/.-]*|github\.com/ollama/ollama/api|google\.golang\.org/genai|github\.com/google/generative-ai-go[\w/.-]*|github\.com/mark3labs/mcp-go[\w/.-]*|github\.com/modelcontextprotocol/go-sdk[\w/.-]*|github\.com/cloudwego/eino[\w/.-]*)"`)
	reStrongAny = regexp.MustCompile(`api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|/v1/chat/completions|/api/generate|/api/chat\b|openrouter\.ai/api`)
	reWeak      = regexp.MustCompile(`(?i)\b(llm|chat_?completions?|tool_calls?|function_call|model_output|generated_code|llm_output|llm_response|assistant_message|agent_output|code_interpreter|run_code|execute_code|exec_code|prompt)\b`)
	reShellFlag = regexp.MustCompile(`shell\s*=\s*True|shell:\s*true|"(ba|z)?sh",\s*"-c"|'(ba|z)?sh',\s*'-c'`)
	reContainer = regexp.MustCompile(`\b(docker|podman|nerdctl)\b|containers\.run\s*\(`)
	reAnnot     = regexp.MustCompile(`toolchain-verify:\s*sandboxed`)
	reNormalize = regexp.MustCompile("[\"'`,\\[\\]{}()=:]+")
	reSpaces    = regexp.MustCompile(`\s+`)

	reNetNone  = regexp.MustCompile(`(?i)(--network|--net|network_mode|networkmode) none\b|(networkdisabled|network_disabled) true\b`)
	reReadOnly = regexp.MustCompile(`(?i)--read-only\b|(read_only|readonlyrootfs) true\b`)
	reCapDrop  = regexp.MustCompile(`(?i)(--cap-drop|cap_drop|capdrop) all\b`)
	reUser     = regexp.MustCompile(`(?i)(?:--user|\s-u|\buser) ([^\s]+)`)
	rePriv     = regexp.MustCompile(`(?i)--privileged\b|privileged true\b|docker\.sock|--pid host|--network host|network_mode host`)
)

func stripComment(line string, lg lang) string {
	t := strings.TrimSpace(line)
	switch lg {
	case langGo, langJS:
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			return ""
		}
	case langPy, langSh:
		if strings.HasPrefix(t, "#") {
			return ""
		}
	}
	return line
}

func llmContext(lg lang, text string, extra []string) (bool, string) {
	var strong *regexp.Regexp
	switch lg {
	case langPy:
		strong = reStrongPy
	case langJS:
		strong = reStrongJS
	case langGo:
		strong = reStrongGo
	}
	if strong != nil {
		if m := strong.FindStringSubmatch(text); m != nil {
			return true, "imports " + m[len(m)-1]
		}
	}
	if m := reStrongAny.FindString(text); m != "" {
		return true, "calls " + m
	}
	for _, e := range extra {
		if strings.Contains(text, e) {
			return true, "contains marker " + e
		}
	}
	seen := map[string]bool{}
	for _, m := range reWeak.FindAllString(text, -1) {
		seen[strings.ToLower(m)] = true
	}
	if len(seen) >= 2 {
		names := make([]string, 0, len(seen))
		for k := range seen {
			names = append(names, k)
		}
		sortStrings(names)
		if len(names) > 3 {
			names = names[:3]
		}
		return true, "LLM identifiers (" + strings.Join(names, ", ") + ")"
	}
	return false, ""
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// hardening returns the missing flags of a container invocation.
func hardening(norm string) (missing []string, unsafe bool) {
	if !reNetNone.MatchString(norm) {
		missing = append(missing, "--network none")
	}
	if !reReadOnly.MatchString(norm) {
		missing = append(missing, "--read-only")
	}
	if !reCapDrop.MatchString(norm) {
		missing = append(missing, "--cap-drop ALL")
	}
	userOK := false
	for _, m := range reUser.FindAllStringSubmatch(norm, -1) {
		v := strings.ToLower(m[1])
		if v != "root" && v != "0" && !strings.HasPrefix(v, "0 ") && v != "none" && !strings.HasPrefix(v, "-") {
			userOK = true
		}
	}
	if !userOK {
		missing = append(missing, "--user nobody")
	}
	return missing, rePriv.MatchString(norm)
}

func normalize(s string) string {
	return reSpaces.ReplaceAllString(reNormalize.ReplaceAllString(s, " "), " ")
}

// sinkKeywords is a cheap literal prefilter: a line can only match a sink
// pattern of its language if it contains one of these.
var sinkKeywords = map[lang][]string{
	langGo: {"exec.Command", "syscall.", "StartProcess"},
	langPy: {"subprocess.", "os.", "pty.spawn", "asyncio.create_subprocess", "exec", "eval"},
	langJS: {"exec", "spawn", "fork", "eval", "Function", "vm.", "Bun.spawn", "Deno.Command"},
	langSh: {"eval", "sh -c"},
}

func hasAny(s string, kws []string) bool {
	for _, k := range kws {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

type sinkHit struct {
	line int
	sp   sinkPat
	m    string
}

func analyze(path string, lg lang, text string, wrappers, markers []string, sev string, rep *Report) []findings.Finding {
	kws := sinkKeywords[lg]
	if !hasAny(text, kws) {
		return nil
	}
	raw := strings.Split(text, "\n")
	code := make([]string, len(raw))
	for i, ln := range raw {
		code[i] = stripComment(ln, lg)
	}
	codeText := strings.Join(code, "\n")
	var active []sinkPat
	for _, sp := range sinks[lg] {
		if sp.need == nil || hasAny(codeText, sp.need) {
			active = append(active, sp)
		}
	}
	var hits []sinkHit
	for i, ln := range code {
		if ln == "" || len(ln) > 4096 || !hasAny(ln, kws) {
			continue
		}
		for _, sp := range active {
			if !hasAny(ln, sp.kw) {
				continue
			}
			if m := sp.re.FindString(ln); m != "" {
				hits = append(hits, sinkHit{i, sp, m})
				break
			}
		}
	}
	rep.Sinks += len(hits)
	if len(hits) == 0 {
		return nil
	}
	llm, why := llmContext(lg, text, markers)
	if !llm {
		return nil
	}
	rep.LLMFiles++
	fileNorm := ""
	out := make([]findings.Finding, 0, len(hits))
	for _, hit := range hits {
		f := classify(hit, path, raw, code, wrappers, why, sev, func() string {
			if fileNorm == "" {
				fileNorm = normalize(codeText)
			}
			return fileNorm
		})
		out = append(out, f)
	}
	return out
}

// classify turns one exec sink in an LLM-context file into a finding.
func classify(hit sinkHit, path string, raw, code, wrappers []string, why, sev string, fileNorm func() string) findings.Finding {
	i, sp := hit.line, hit.sp
	call := strings.TrimLeft(strings.TrimSpace(hit.m), " \t;&|(")
	call = strings.TrimSpace(strings.TrimSuffix(call, "("))
	lo, hi := max(0, i-8), min(len(code), i+16)
	window := strings.Join(code[lo:hi], "\n")
	f := findings.Finding{Path: path, Line: i + 1, Severity: findings.SevInfo}
	if reAnnot.MatchString(raw[i]) || (i > 0 && reAnnot.MatchString(raw[i-1])) {
		f.Rule, f.Message = "exec.annotated", call+" marked as sandboxed by a toolchain-verify:sandboxed comment (not verified)"
		return f
	}
	if w := wrapperIn(window, wrappers); w != "" {
		f.Rule, f.Message = "exec.wrapped", call+" goes through approved wrapper "+w
		return f
	}
	if sp.kind != "code" && reContainer.MatchString(window) {
		missing, unsafe := hardening(normalize(window) + " " + fileNorm())
		switch {
		case unsafe:
			f.Rule, f.Severity, f.Fix = "exec.weak-sandbox", findings.SevFail, fixText
			f.Message = fmt.Sprintf("%s starts a container with --privileged, host namespaces or the Docker socket in a file that handles LLM output (%s)", call, why)
		case len(missing) > 0:
			f.Rule, f.Severity, f.Fix = "exec.weak-sandbox", sev, fixText
			f.Message = fmt.Sprintf("%s starts a container without %s in a file that handles LLM output (%s)", call, strings.Join(missing, ", "), why)
		default:
			f.Rule, f.Message = "exec.wrapped", call+" runs in a hardened container"
		}
		return f
	}
	f.Rule, f.Severity, f.Fix = "exec.unwrapped", sev, fixText
	what := "runs a process"
	switch sp.kind {
	case "code":
		f.Rule, what = "exec.dynamic-code", "evaluates code in-process"
	case "shell":
		what = "runs a shell command"
	}
	f.Message = fmt.Sprintf("%s %s outside a hardened container in a file that handles LLM output (%s)", call, what, why)
	if sp.kind != "code" && reShellFlag.MatchString(window) {
		f.Message += " [shell]"
	}
	return f
}

func wrapperIn(window string, wrappers []string) string {
	for _, w := range wrappers {
		if strings.Contains(window, w) {
			return w
		}
	}
	return ""
}
