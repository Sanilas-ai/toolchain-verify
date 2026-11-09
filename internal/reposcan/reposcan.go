// Package reposcan is a read-only scanner for repository content that AI
// coding agents, editors and package managers trust: nested instruction
// files, MCP/agent/editor configs and hooks, CI workflows and install-time
// package hooks, plus hidden (invisible Unicode, HTML-hidden) text anywhere.
//
// It only reads bytes. It never runs git, a package manager, an interpreter,
// an MCP server or an agent; it never follows symlinks; every file read is
// bounded. Anything it could not read or parse is reported as incomplete —
// an incomplete scan is never a PASS.
package reposcan

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

// Severities (shared with the other audits).
const (
	SevFail = findings.SevFail
	SevWarn = findings.SevWarn
	SevInfo = findings.SevInfo
)

// Verdicts.
const (
	VerdictPass       = "PASS"
	VerdictWarn       = "WARN"
	VerdictFail       = "FAIL"
	VerdictIncomplete = "INCOMPLETE"
)

// ErrRefused is returned for scan roots that must not be walked.
var ErrRefused = errors.New("refused scan root")

// Options bound the scan. Zero values take the defaults.
type Options struct {
	MaxFileSize  int64         // per-file read cap (default 1 MiB)
	MaxFiles     int           // directory entries visited (default 200000)
	MaxDepth     int           // directory depth below root (default 40)
	MaxTotal     int64         // total bytes read (default 1 GiB)
	Timeout      time.Duration // wall clock (default 5m)
	IncludeDeps  bool          // also walk node_modules, .venv, vendor, ...
	Baseline     *Baseline     // approved control-file inventory
	IOCs         *IOCDB        // indicator DB (default: embedded)
	Ignore       []string      // "rule" or "rule:path-glob"
	StrictImages bool          // unscanned images/archives make the scan incomplete
	Home         string        // refused as a root (default $HOME)
}

func (o *Options) defaults() {
	if o.MaxFileSize <= 0 {
		o.MaxFileSize = 1 << 20
	}
	if o.MaxFiles <= 0 {
		o.MaxFiles = 200000
	}
	if o.MaxDepth <= 0 {
		o.MaxDepth = 40
	}
	if o.MaxTotal <= 0 {
		o.MaxTotal = 1 << 30
	}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Minute
	}
	if o.Home == "" {
		o.Home, _ = os.UserHomeDir()
	}
}

// Finding is one observation. Path is relative to the scan root
// (slash-separated); Offset is a byte offset into the file; Evidence is an
// escaped, redacted excerpt (never raw hidden text).
type Finding struct {
	Rule     string   `json:"rule"`
	Severity string   `json:"severity"`
	Path     string   `json:"path,omitempty"`
	Line     int      `json:"line,omitempty"`
	Offset   int      `json:"offset,omitempty"`
	Message  string   `json:"message"`
	Evidence string   `json:"evidence,omitempty"`
	Decoded  string   `json:"decoded,omitempty"`
	Signals  []string `json:"signals,omitempty"`
	Fix      string   `json:"fix,omitempty"`
	Refs     []string `json:"refs,omitempty"`
}

// ControlFile is one entry of the control-file inventory.
type ControlFile struct {
	Path    string `json:"path"`
	Kind    string `json:"kind"`
	SHA256  string `json:"sha256,omitempty"`
	Size    int64  `json:"size"`
	Symlink string `json:"symlink,omitempty"`
}

// Coverage records what was and was not examined.
type Coverage struct {
	Files        int            `json:"files"`
	BytesRead    int64          `json:"bytes_read"`
	SkippedDirs  []string       `json:"skipped_dirs,omitempty"`
	NotChecked   map[string]int `json:"not_checked,omitempty"`   // images, archives, binaries, special files
	PartialFiles []string       `json:"partial_files,omitempty"` // only the first MaxFileSize bytes scanned
	Incomplete   []string       `json:"incomplete,omitempty"`    // reasons the verdict cannot be PASS
	SemanticNote string         `json:"semantic_note,omitempty"` // static scan limits
}

// Report is the result of Scan.
type Report struct {
	Root       string        `json:"root"`
	Verdict    string        `json:"verdict"`
	IOCVersion string        `json:"ioc_db,omitempty"`
	Findings   []Finding     `json:"findings"`
	Inventory  []ControlFile `json:"control_files"`
	Coverage   Coverage      `json:"coverage"`
	Ignored    int           `json:"ignored,omitempty"`
}

// Counts per severity.
func (r *Report) Counts() (fail, warn, info int) {
	for _, f := range r.Findings {
		switch f.Severity {
		case SevFail:
			fail++
		case SevWarn:
			warn++
		default:
			info++
		}
	}
	return
}

type scanner struct {
	opt      Options
	root     string
	rep      *Report
	seen     map[string]bool
	deadline time.Time
	stopped  bool
	// mcp/hook/task commands referencing repo files, checked after the walk
	refs []cmdRef
	// files present, for IOC path checks
	present map[string]bool
	// directories holding a SKILL.md: scripts there run as agent tools
	skillDirs []string
}

type cmdRef struct {
	from, cmd string
	line      int
	rule      string
}

var depDirs = map[string]bool{"node_modules": true, ".venv": true, "venv": true, "site-packages": true, "vendor": true, "bower_components": true, ".tox": true, ".nox": true, "target": false}

// Scan walks root read-only and returns a report. err is non-nil only for
// refused or unusable roots.
func Scan(root string, opt Options) (*Report, error) {
	opt.defaults()
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(real)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s: not a directory", root)
	}
	if real == "/" || (opt.Home != "" && filepath.Clean(real) == filepath.Clean(opt.Home)) {
		return nil, fmt.Errorf("%w: %s (scan a repository, not / or $HOME)", ErrRefused, real)
	}
	if opt.IOCs == nil {
		opt.IOCs, err = EmbeddedIOCs()
		if err != nil {
			return nil, err
		}
	}
	s := &scanner{opt: opt, root: real, seen: map[string]bool{}, present: map[string]bool{},
		deadline: time.Now().Add(opt.Timeout),
		rep: &Report{Root: real, IOCVersion: opt.IOCs.Version + " (" + opt.IOCs.Updated + ")",
			Coverage: Coverage{NotChecked: map[string]int{},
				SemanticNote: "static scan: catches known patterns, hidden text and risky configs; it cannot prove the absence of a semantic prompt injection; images are not OCR-checked"}}}
	s.walk()
	s.checkRefs()
	if opt.Baseline != nil {
		s.compareBaseline()
	}
	s.finish()
	return s.rep, nil
}

func (s *scanner) incomplete(reason string) {
	s.rep.Coverage.Incomplete = append(s.rep.Coverage.Incomplete, reason)
}

func (s *scanner) add(f Finding) {
	key := f.Rule + "\x00" + f.Path + "\x00" + fmt.Sprint(f.Line, f.Offset) + "\x00" + f.Message
	if s.seen[key] {
		return
	}
	s.seen[key] = true
	if findings.Ignored(s.opt.Ignore, findings.Finding{Rule: f.Rule, Path: f.Path}) {
		s.rep.Ignored++
		return
	}
	s.rep.Findings = append(s.rep.Findings, f)
}

func (s *scanner) walk() {
	err := filepath.WalkDir(s.root, func(p string, d fs.DirEntry, err error) error {
		rel, _ := filepath.Rel(s.root, p)
		rel = filepath.ToSlash(rel)
		if err != nil {
			s.incomplete(fmt.Sprintf("%s: %v", rel, err))
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if time.Now().After(s.deadline) {
			s.incomplete(fmt.Sprintf("timeout after %s", s.opt.Timeout))
			s.stopped = true
			return filepath.SkipAll
		}
		s.rep.Coverage.Files++
		if s.rep.Coverage.Files > s.opt.MaxFiles {
			s.incomplete(fmt.Sprintf("stopped after %d entries (--max-files)", s.opt.MaxFiles))
			s.stopped = true
			return filepath.SkipAll
		}
		if d.IsDir() {
			if p == s.root {
				return nil
			}
			name := d.Name()
			if name == ".git" || name == ".hg" || name == ".svn" {
				// VCS internals: never read (repo-controlled hooks,
				// filters and pagers are irrelevant to a byte scan).
				return filepath.SkipDir
			}
			if depDirs[name] && !s.opt.IncludeDeps {
				s.rep.Coverage.SkippedDirs = append(s.rep.Coverage.SkippedDirs, rel)
				return filepath.SkipDir
			}
			if strings.Count(rel, "/")+1 > s.opt.MaxDepth {
				s.incomplete(fmt.Sprintf("%s: deeper than --max-depth %d", rel, s.opt.MaxDepth))
				return filepath.SkipDir
			}
			return nil
		}
		s.present[strings.ToLower(rel)] = true
		switch t := d.Type(); {
		case t&fs.ModeSymlink != 0:
			s.symlink(p, rel)
		case t.IsRegular():
			s.file(p, rel)
		default:
			s.rep.Coverage.NotChecked["special-file"]++
			if classify(rel) != "" {
				s.incomplete(rel + ": control file is not a regular file (fifo/device/socket); not opened")
				s.add(Finding{Rule: "fs.special-control-file", Severity: SevWarn, Path: rel, Message: "control file is a fifo, device or socket; it was not opened"})
			}
		}
		return nil
	})
	if err != nil {
		s.incomplete("walk: " + err.Error())
	}
}

// symlink records links without following them. A link that leaves the
// root can make an agent load (or a reviewer miss) arbitrary files.
func (s *scanner) symlink(p, rel string) {
	target, err := os.Readlink(p)
	if err != nil {
		s.incomplete(rel + ": unreadable symlink")
		return
	}
	kind := classify(rel)
	resolved := target
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(filepath.Dir(p), resolved)
	}
	resolved = filepath.Clean(resolved)
	inside := resolved == s.root || strings.HasPrefix(resolved, s.root+string(filepath.Separator))
	if inside {
		// A chain could still leave the root; resolve fully without reading.
		if r2, err := filepath.EvalSymlinks(p); err == nil {
			inside = r2 == s.root || strings.HasPrefix(r2, s.root+string(filepath.Separator))
		}
	}
	if kind != "" {
		s.rep.Inventory = append(s.rep.Inventory, ControlFile{Path: rel, Kind: kind, Symlink: escapeEvidence(target, 200)})
	}
	if !inside {
		sev := SevWarn
		msg := "symlink points outside the scanned tree; not followed"
		if kind != "" {
			sev = SevFail
			msg = "control file (" + kind + ") is a symlink to outside the repository; an agent would load a file nobody reviewed"
			s.incomplete(rel + ": control file symlink escapes the root; target not scanned")
		}
		s.add(Finding{Rule: "fs.symlink-escape", Severity: sev, Path: rel, Message: msg, Evidence: "-> " + escapeEvidence(target, 200),
			Fix: "replace the link with a regular file or remove it"})
	}
}

// readBounded opens a regular file without following symlinks and reads at
// most limit bytes. partial is set when the file is larger.
func (s *scanner) readBounded(p string, limit int64) (b []byte, size int64, partial bool, err error) {
	f, err := openNoFollow(p)
	if err != nil {
		return nil, 0, false, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, 0, false, err
	}
	if !st.Mode().IsRegular() {
		return nil, 0, false, errors.New("not a regular file")
	}
	size = st.Size()
	if s.rep.Coverage.BytesRead >= s.opt.MaxTotal {
		return nil, size, false, errors.New("total read budget exhausted (--max-total)")
	}
	if remain := s.opt.MaxTotal - s.rep.Coverage.BytesRead; limit > remain {
		limit = remain
	}
	b, err = io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, size, false, err
	}
	if int64(len(b)) > limit {
		b = b[:limit]
		partial = true
	}
	s.rep.Coverage.BytesRead += int64(len(b))
	return b, size, partial, nil
}

func (s *scanner) file(p, rel string) {
	base := path.Base(rel)
	ext := strings.ToLower(path.Ext(base))
	kind := classify(rel)

	if kind == "" && imageExt[ext] {
		s.rep.Coverage.NotChecked["images"]++
		return
	}
	if kind == "" && archiveExt[ext] {
		s.rep.Coverage.NotChecked["archives"]++
		s.hashIOCFile(p, rel)
		return
	}
	b, size, partial, err := s.readBounded(p, s.opt.MaxFileSize)
	if err != nil {
		if kind != "" {
			s.incomplete(rel + ": " + err.Error())
			s.add(Finding{Rule: "scan.read-error", Severity: SevWarn, Path: rel, Message: "control file could not be read: " + err.Error()})
		} else {
			s.rep.Coverage.NotChecked["unreadable"]++
			if strings.Contains(err.Error(), "budget") {
				s.incomplete(rel + ": " + err.Error())
			}
		}
		return
	}
	if kind != "" {
		cf := ControlFile{Path: rel, Kind: kind, Size: size}
		if !partial {
			sum := sha256.Sum256(b)
			cf.SHA256 = hex.EncodeToString(sum[:])
		}
		s.rep.Inventory = append(s.rep.Inventory, cf)
		if partial {
			s.incomplete(fmt.Sprintf("%s: control file larger than --max-file-size (%d > %d bytes)", rel, size, s.opt.MaxFileSize))
			s.add(Finding{Rule: "scan.oversized-control-file", Severity: SevWarn, Path: rel,
				Message: fmt.Sprintf("control file is %d bytes; only the first %d were scanned (agents load the whole file)", size, s.opt.MaxFileSize)})
		}
	}
	binary := isBinary(b)
	if binary && kind == "" {
		s.rep.Coverage.NotChecked["binaries"]++
		s.hashIOCBytes(rel, b, partial)
		return
	}
	if partial && kind == "" {
		s.rep.Coverage.PartialFiles = append(s.rep.Coverage.PartialFiles, rel)
	}
	if kind != "" && !utf8.Valid(b) && !partial {
		s.incomplete(rel + ": control file is not valid UTF-8")
		s.add(Finding{Rule: "encoding.invalid-utf8", Severity: SevWarn, Path: rel,
			Message: "control file is not valid UTF-8; clients may decode it differently than this scanner"})
	}
	s.hashIOCBytes(rel, b, partial)
	if kind == KindInstructions && strings.EqualFold(base, "skill.md") {
		s.skillDirs = append(s.skillDirs, path.Dir(rel))
	}
	if kind == "" && isScriptName(rel) && !isDataName(rel) {
		for _, d := range s.skillDirs {
			if d == "." || strings.HasPrefix(rel, d+"/") {
				s.rep.Inventory = append(s.rep.Inventory, ControlFile{Path: rel, Kind: KindSkillScript, Size: size, SHA256: sha(b, partial)})
				s.judgeSkillScript(rel, b)
				break
			}
		}
	}
	s.scanText(rel, kind, b)
	switch kind {
	case KindMCP, KindAgentConfig, KindEditorTasks, KindEditorConfig:
		if strings.HasSuffix(strings.ToLower(base), ".yml") {
			s.scanTextControl(rel, kind, b)
			break
		}
		s.scanJSONConfig(rel, kind, b)
	case KindCodexConfig:
		s.scanCodexConfig(rel, b)
	case KindWorkflow:
		s.scanWorkflow(rel, b)
	case KindPackageHook:
		s.scanPackageHook(rel, b)
	case KindInstructions:
		s.scanTextControl(rel, kind, b)
	}
}

// isBinary: a NUL byte in the first 8 KiB.
func isBinary(b []byte) bool {
	n := len(b)
	if n > 8192 {
		n = 8192
	}
	for _, c := range b[:n] {
		if c == 0 {
			return true
		}
	}
	return false
}

func sha(b []byte, partial bool) string {
	if partial {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// isDataName: structured data next to a skill is not a script.
func isDataName(rel string) bool {
	switch strings.ToLower(path.Ext(rel)) {
	case ".json", ".yml", ".yaml", ".toml":
		return true
	}
	return false
}

func (s *scanner) finish() {
	sort.SliceStable(s.rep.Findings, func(i, j int) bool {
		a, b := s.rep.Findings[i], s.rep.Findings[j]
		if ra, rb := findings.Rank(a.Severity), findings.Rank(b.Severity); ra != rb {
			return ra < rb
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Line < b.Line
	})
	sort.Slice(s.rep.Inventory, func(i, j int) bool { return s.rep.Inventory[i].Path < s.rep.Inventory[j].Path })
	if s.rep.Inventory == nil {
		s.rep.Inventory = []ControlFile{}
	}
	if s.opt.StrictImages {
		for _, k := range []string{"images", "archives", "binaries"} {
			if n := s.rep.Coverage.NotChecked[k]; n > 0 {
				s.incomplete(fmt.Sprintf("%d %s not checked (--strict-coverage)", n, k))
			}
		}
	}
	fail, warn, _ := s.rep.Counts()
	switch {
	case fail > 0:
		s.rep.Verdict = VerdictFail
	case len(s.rep.Coverage.Incomplete) > 0:
		s.rep.Verdict = VerdictIncomplete
	case warn > 0:
		s.rep.Verdict = VerdictWarn
	default:
		s.rep.Verdict = VerdictPass
	}
	if s.rep.Findings == nil {
		s.rep.Findings = []Finding{}
	}
}
