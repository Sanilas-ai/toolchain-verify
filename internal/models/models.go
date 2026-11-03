// Package models implements `toolchain-verify models`: a read-only scanner
// for ML model artifacts (GGUF, safetensors, pickle/torch, numpy, Keras)
// and Ollama model stores. Files are parsed, never deserialized: pickle
// streams are walked opcode by opcode to list the globals they would import.
package models

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

// Options are run-time inputs that are not part of the policy.
type Options struct {
	Paths       []string // extra files/directories to scan
	Strict      bool
	NoOllama    bool
	NoAPI       bool
	VerifyBlobs bool
	NoHash      bool
	External    string // overrides policy.External when set
	Workers     int
	APITimeout  time.Duration
	Getenv      func(string) string
	LookPath    func(string) (string, error)
}

// Artifact is one scanned file.
type Artifact struct {
	Path     string            `json:"path"`
	Size     int64             `json:"size"`
	SHA256   string            `json:"sha256,omitempty"`
	Format   string            `json:"format"`
	Source   string            `json:"source"` // "path" or "ollama"
	Models   []string          `json:"models,omitempty"`
	Layer    string            `json:"layer,omitempty"`
	Details  string            `json:"details,omitempty"`
	Pickle   bool              `json:"pickle,omitempty"`
	Imports  []string          `json:"imports,omitempty"`
	Allowed  string            `json:"allowed,omitempty"`
	Scanners map[string]string `json:"scanners,omitempty"`
}

// Report is the result of a run.
type Report struct {
	OK        bool               `json:"ok"`
	Strict    bool               `json:"strict"`
	Roots     []string           `json:"roots"`
	Artifacts []Artifact         `json:"artifacts"`
	Scanners  map[string]string  `json:"scanners"`
	Ollama    *OllamaReport      `json:"ollama,omitempty"`
	Truncated bool               `json:"truncated,omitempty"`
	Findings  []findings.Finding `json:"findings"`
	Ignored   int                `json:"ignored,omitempty"`
}

// ErrRefused is returned for scan roots that would walk the whole system.
var ErrRefused = errors.New("refused")

const (
	maxEntries = 500000
	maxPickle  = 4 << 30
)

var skipDirs = map[string]bool{".git": true, ".hg": true, ".svn": true, "__pycache__": true, "node_modules": true, ".ssh": true, ".gnupg": true}

type job struct {
	path   string
	source string
	layer  string
	models []string
	expect string // expected sha256 (Ollama / HF blob name)
	refSz  int64  // size from the manifest, -1 unknown
}

type result struct {
	art       Artifact
	fa        *facts
	err       error
	writable  bool
	digestBad bool
}

func defaultStores(getenv func(string) string) []string {
	var out []string
	if v := getenv("OLLAMA_MODELS"); v != "" {
		out = append(out, v)
	}
	if h, err := os.UserHomeDir(); err == nil {
		out = append(out, filepath.Join(h, ".ollama", "models"))
	}
	return append(out, "/usr/share/ollama/.ollama/models", "/var/lib/ollama/.ollama/models", "/var/lib/ollama/models")
}

// Run scans the configured roots and Ollama stores.
func Run(pol *Policy, opt Options) (*Report, error) {
	if pol == nil {
		pol = &Policy{}
	}
	if err := pol.Validate(); err != nil {
		return nil, err
	}
	if opt.Getenv == nil {
		opt.Getenv = os.Getenv
	}
	if opt.LookPath == nil {
		opt.LookPath = exec.LookPath
	}
	if opt.Workers <= 0 {
		opt.Workers = 4
	}
	if opt.APITimeout <= 0 {
		opt.APITimeout = 5 * time.Second
	}
	ext := pol.external()
	if opt.External != "" {
		ext = opt.External
	}
	c := &findings.Collector{Ignore: pol.Ignore}
	rep := &Report{Strict: opt.Strict, Scanners: map[string]string{}}

	// 1. scan roots
	var roots []string
	fromCLI := map[string]bool{}
	for i, r := range append(append([]string(nil), pol.Roots...), opt.Paths...) {
		r = filepath.Clean(expandHome(r))
		if a, err := filepath.Abs(r); err == nil {
			r = a
		}
		if r == "/" {
			return nil, fmt.Errorf("%w: scanning / is not supported; list model directories", ErrRefused)
		}
		roots = append(roots, r)
		if i >= len(pol.Roots) {
			fromCLI[r] = true
		}
	}
	rep.Roots = roots
	var jobs []job
	seen := map[string]bool{}
	entries := 0
	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil {
			sev := findings.SevWarn
			if errors.Is(err, fs.ErrNotExist) && !fromCLI[root] {
				sev = findings.SevInfo // optional configured root (e.g. an HF cache) not present here
			}
			c.Add(findings.Finding{Rule: "models.unreadable", Severity: sev, Path: root, Message: "scan root not readable: " + errText(err)})
			continue
		}
		if !info.IsDir() {
			if rp, err := filepath.EvalSymlinks(root); err == nil && !seen[rp] {
				seen[rp] = true
				jobs = append(jobs, job{path: root, source: "path", expect: hfBlobDigest(rp), refSz: -1})
			}
			continue
		}
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if d != nil && d.IsDir() && p != root {
					c.Add(findings.Finding{Rule: "models.unreadable", Severity: findings.SevInfo, Path: p, Message: "directory not readable: " + errText(err)})
					return filepath.SkipDir
				}
				return nil
			}
			entries++
			if entries > maxEntries {
				rep.Truncated = true
				return filepath.SkipAll
			}
			if d.IsDir() {
				if p == root {
					return nil
				}
				if skipDirs[d.Name()] || excluded(p, pol.Exclude) {
					return filepath.SkipDir
				}
				rel, _ := filepath.Rel(root, p)
				if strings.Count(rel, string(filepath.Separator))+1 > pol.maxDepth() {
					return filepath.SkipDir
				}
				return nil
			}
			if !IsArtifactName(d.Name()) || excluded(p, pol.Exclude) {
				return nil
			}
			rp := p
			if d.Type()&fs.ModeSymlink != 0 { // Hugging Face snapshots link into blobs/
				t, err := filepath.EvalSymlinks(p)
				if err != nil {
					return nil
				}
				if st, err := os.Stat(t); err != nil || !st.Mode().IsRegular() {
					return nil
				}
				rp = t
			} else if !d.Type().IsRegular() {
				return nil
			}
			if seen[rp] {
				return nil
			}
			seen[rp] = true
			jobs = append(jobs, job{path: p, source: "path", expect: hfBlobDigest(rp), refSz: -1})
			return nil
		})
	}
	if rep.Truncated {
		c.Add(findings.Finding{Rule: "models.truncated", Severity: findings.SevWarn, Message: fmt.Sprintf("stopped after %d directory entries; narrow models.roots", maxEntries)})
	}

	// 2. Ollama
	var stores []*storeScan
	o := pol.Ollama
	if o.enabled() && !opt.NoOllama {
		or := &OllamaReport{}
		rep.Ollama = or
		dirs := defaultStores(opt.Getenv)
		explicit := o != nil && len(o.ModelsDirs) > 0
		if explicit {
			dirs = o.ModelsDirs
		}
		done := map[string]bool{}
		for _, d := range dirs {
			d = filepath.Clean(expandHome(d))
			if done[d] {
				continue
			}
			done[d] = true
			if _, err := os.Stat(filepath.Join(d, "blobs")); err != nil {
				if explicit {
					c.Add(findings.Finding{Rule: "ollama.store-unreadable", Severity: findings.SevWarn, Path: d, Message: "no readable blobs/ directory: " + errText(err)})
				}
				continue
			}
			s := scanStore(d, o.registries())
			stores = append(stores, s)
			keyPerms(c, d)
		}
		if o.api() && !opt.NoAPI {
			or.URL = o.url(opt.Getenv)
			v, ms, err := queryAPI(or.URL, opt.APITimeout)
			or.Version, or.APIModels = v, ms
			if err != nil {
				or.APIError = err.Error()
				sev := findings.SevInfo
				if o != nil && o.URL != "" {
					sev = findings.SevWarn
				}
				c.Add(findings.Finding{Rule: "ollama.api-unreachable", Severity: sev, Path: or.URL, Message: "Ollama API not reachable: " + err.Error()})
			} else if !isLoopbackURL(or.URL) {
				c.Add(findings.Finding{Rule: "ollama.api-remote", Severity: findings.SevInfo, Path: or.URL, Message: "Ollama API is not on loopback; its blobs cannot be checked from here"})
			}
		}
		weights := map[string]bool{"model": true, "projector": true, "adapter": true, "draft": true}
		for _, s := range stores {
			byPath := map[string]int{}
			for _, r := range s.refs {
				if !weights[r.kind] {
					continue
				}
				if _, ok := s.blobs[r.digest]; !ok {
					continue
				}
				bp := blobPath(s.store.Dir, r.digest)
				if i, ok := byPath[bp]; ok {
					jobs[i].models = appendUniq(jobs[i].models, r.model)
					continue
				}
				byPath[bp] = len(jobs)
				jobs = append(jobs, job{path: bp, source: "ollama", layer: r.kind, models: []string{r.model}, expect: r.digest, refSz: r.size})
			}
		}
	}

	// 3. inspect (parallel)
	hashAll := pol.hash() && !opt.NoHash
	verify := opt.VerifyBlobs || (o != nil && o.VerifyBlobs)
	results := make([]result, len(jobs))
	var wg sync.WaitGroup
	ch := make(chan int)
	for w := 0; w < opt.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range ch {
				results[i] = process(jobs[i], pol, hashAll, verify)
			}
		}()
	}
	for i := range jobs {
		ch <- i
	}
	close(ch)
	wg.Wait()

	// 4. external scanners
	var scs []scanner
	if ext != "off" {
		scs = findScanners(pol.scanners(), opt.LookPath)
		for _, s := range scs {
			rep.Scanners[s.name] = s.path
		}
	}
	pickles := 0
	for i := range results {
		r := &results[i]
		if r.err != nil || r.fa == nil {
			continue
		}
		if r.fa.pickle {
			pickles++
		}
		for _, s := range scs {
			if !s.handles(r.fa.format, r.fa.pickle) {
				continue
			}
			st, sum := s.run(r.art.Path, pol.scannerTimeout())
			if r.art.Scanners == nil {
				r.art.Scanners = map[string]string{}
			}
			r.art.Scanners[s.name] = st
			switch st {
			case ScanIssues:
				c.Add(findings.Finding{Rule: "models.scanner", Severity: findings.SevFail, Path: r.art.Path, Message: s.name + " reported issues: " + sum})
			case ScanError:
				c.Add(findings.Finding{Rule: "models.scanner-error", Severity: findings.SevWarn, Path: r.art.Path, Message: s.name + " failed: " + sum})
			}
		}
	}
	if ext != "off" && len(scs) == 0 && pickles > 0 {
		sev := findings.SevWarn
		if ext == "require" {
			sev = findings.SevFail
		}
		c.Add(findings.Finding{Rule: "models.scanner-missing", Severity: sev,
			Message: fmt.Sprintf("%d pickle-based artifact(s) and neither %s is installed; only the built-in opcode scan was used", pickles, strings.Join(pol.scanners(), " nor ")),
			Fix:     "install picklescan/modelscan in a sandbox or venv (pipx install picklescan) and re-run; this tool never installs them"})
	} else if ext == "require" && len(scs) == 0 {
		c.Add(findings.Finding{Rule: "models.scanner-missing", Severity: findings.SevFail, Message: "models.external = \"require\" but no scanner (" + strings.Join(pol.scanners(), ", ") + ") was found"})
	}

	// 5. judge
	for i := range results {
		judge(c, pol, &results[i])
		if results[i].err == nil {
			rep.Artifacts = append(rep.Artifacts, results[i].art)
		}
	}
	for _, s := range stores {
		judgeStore(c, s, results, jobs, verify)
		rep.Ollama.Stores = append(rep.Ollama.Stores, s.store)
	}
	if rep.Ollama != nil {
		judgeAPI(c, rep.Ollama, stores)
	}
	rep.Findings = c.Sorted()
	rep.Ignored = c.Ignored
	rep.OK = findings.OK(rep.Findings, opt.Strict)
	return rep, nil
}

func appendUniq(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func excluded(p string, ex []string) bool {
	for _, g := range ex {
		if matchGlob(g, p) {
			return true
		}
	}
	return false
}

// hfBlobDigest returns the expected digest of a Hugging Face hub blob
// (.../blobs/<sha256>); other files have none.
func hfBlobDigest(p string) string {
	if filepath.Base(filepath.Dir(p)) == "blobs" && hexRe.MatchString(filepath.Base(p)) {
		return filepath.Base(p)
	}
	return ""
}

func needHash(pol *Policy, path string) bool {
	for _, a := range pol.Allow {
		if a.Path == "" || matchGlob(a.Path, path) {
			return true
		}
	}
	return false
}

func process(j job, pol *Policy, hashAll, verify bool) result {
	r := result{art: Artifact{Path: j.path, Source: j.source, Layer: j.layer, Models: j.models}}
	st, err := os.Stat(j.path)
	if err != nil {
		r.err = err
		return r
	}
	r.art.Size = st.Size()
	if st.Mode().Perm()&0o002 != 0 {
		r.writable = true
	} else if dst, err := os.Stat(filepath.Dir(j.path)); err == nil && dst.Mode().Perm()&0o002 != 0 && dst.Mode()&os.ModeSticky == 0 {
		r.writable = true
	}
	doHash := (j.source == "path" && hashAll) || (j.source == "ollama" && verify) || needHash(pol, j.path) || (j.source == "path" && j.expect != "")
	if doHash {
		h, err := hashFile(j.path)
		if err != nil {
			r.err = err
			return r
		}
		r.art.SHA256 = h
		if j.expect != "" && h != j.expect {
			r.digestBad = true
		}
	} else if j.source == "ollama" {
		r.art.SHA256 = j.expect // from the content-addressed name (not re-hashed)
	}
	fa, err := inspect(j.path, st.Size(), maxPickle)
	if err != nil {
		r.err = err
		return r
	}
	r.fa = fa
	r.art.Format, r.art.Details, r.art.Pickle = fa.format, fa.details, fa.pickle
	r.art.Imports = fa.imports
	return r
}

func hashFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.CopyBuffer(h, f, make([]byte, 1<<20)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func judge(c *findings.Collector, pol *Policy, r *result) {
	a := &r.art
	if r.err != nil {
		c.Add(findings.Finding{Rule: "models.unreadable", Severity: findings.SevWarn, Path: a.Path, Message: "cannot read: " + errText(r.err)})
		return
	}
	fa := r.fa
	rulePrefix := "models."
	if a.Source == "ollama" {
		rulePrefix = "ollama."
	}
	if r.writable {
		c.Add(findings.Finding{Rule: rulePrefix + "writable", Severity: findings.SevFail, Path: a.Path,
			Message: "artifact or its directory is world-writable: another local user can replace it before it is loaded", Fix: "chmod o-w (or a sticky directory)"})
	}
	if r.digestBad {
		rule, what := "models.digest-mismatch", "Hugging Face blob name"
		if a.Source == "ollama" {
			rule, what = "ollama.blob-digest", "content-addressed blob name"
		}
		c.Add(findings.Finding{Rule: rule, Severity: findings.SevFail, Path: a.Path,
			Message: fmt.Sprintf("SHA-256 %s does not match the %s: the file was modified or corrupted", short(a.SHA256), what), Fix: "delete it and download it again from a trusted source"})
	}
	// pins
	for _, al := range pol.Allow {
		if al.Path != "" && isLiteral(al.Path) && filepath.Clean(expandHome(al.Path)) == a.Path && a.SHA256 != "" && a.SHA256 != al.SHA256 {
			c.Add(findings.Finding{Rule: "models.digest-mismatch", Severity: findings.SevFail, Path: a.Path,
				Message: fmt.Sprintf("SHA-256 %s differs from the pinned %s", short(a.SHA256), short(al.SHA256)), Fix: "verify the new file and update models.allow, or restore the reviewed one"})
		}
		if a.SHA256 == al.SHA256 && (al.Path == "" || matchGlob(al.Path, a.Path)) {
			a.Allowed = or(al.Note, "allowlisted")
		}
	}
	if len(fa.malformed) > 0 {
		rule := rulePrefix + "malformed"
		switch fa.format {
		case FmtGGUF:
			rule = rulePrefix + "gguf-malformed"
		case FmtSafetensors:
			rule = rulePrefix + "safetensors-malformed"
		}
		c.Add(findings.Finding{Rule: rule, Severity: findings.SevFail, Path: a.Path,
			Message: "structure check failed (malformed or crafted file; parser bugs in loaders are a known attack surface): " + strings.Join(fa.malformed, "; "),
			Fix:     "do not load it; re-download from the original source"})
	}
	for _, t := range fa.templates {
		sev := findings.SevWarn
		if t.fail {
			sev = findings.SevFail
		}
		c.Add(findings.Finding{Rule: rulePrefix + "gguf-template", Severity: sev, Path: a.Path,
			Message: fmt.Sprintf("%s contains %s; Jinja-rendering loaders (llama-cpp-python, transformers) can be exploited via chat templates (CVE-2024-34359)", t.key, t.label),
			Fix:     "use a sandboxed Jinja environment or replace the template", Refs: []string{"https://github.com/advisories/GHSA-56xg-wfcc-g829"}})
	}
	if fa.lambda {
		c.Add(findings.Finding{Rule: "models.keras-lambda", Severity: findings.SevWarn, Path: a.Path,
			Message: "Keras model contains a Lambda layer (serialized Python code)", Fix: "load with keras.models.load_model(..., safe_mode=True) or rebuild without Lambda"})
	}
	if !fa.pickle {
		return
	}
	trusted := a.Allowed != ""
	for _, g := range pol.Trusted {
		if matchGlob(g, a.Path) {
			trusted = true
		}
	}
	var dangerous, unknown []string
	safe := 0
	for _, g := range fa.imports {
		switch ClassifyImport(g) {
		case ImportDangerous:
			dangerous = append(dangerous, g)
		case ImportUnknown:
			unknown = append(unknown, g)
		default:
			safe++
		}
	}
	if len(dangerous) > 0 {
		c.Add(findings.Finding{Rule: "models.pickle-dangerous", Severity: findings.SevFail, Path: a.Path,
			Message: "pickle imports " + list(dangerous, 6) + " — loading this file runs that code",
			Fix:     "do not load it; report it to the publisher", Refs: []string{"https://docs.python.org/3/library/pickle.html"}})
	}
	if len(unknown) > 0 {
		sev := pol.unknownSev()
		if trusted {
			sev = findings.SevInfo
		}
		c.Add(findings.Finding{Rule: "models.pickle-unknown-import", Severity: sev, Path: a.Path,
			Message: "pickle imports globals outside the known-safe list: " + list(unknown, 6),
			Fix:     "review these classes; load with torch.load(weights_only=True) or convert to safetensors"})
	}
	sev := pol.pickleSev()
	if trusted {
		sev = findings.SevInfo
	}
	msg := fmt.Sprintf("pickle-based artifact (%s); loading it with pickle/torch.load(weights_only=False)/joblib executes the stream", fa.format)
	if len(fa.imports) > 0 {
		msg += fmt.Sprintf("; %d import(s), %d known safe", len(fa.imports), safe)
	} else if fa.partial == "" {
		msg += "; as scanned it is data-only (imports no callables), but the format allows code if the file is replaced"
	}
	if a.Allowed != "" {
		msg += "; allowlisted: " + a.Allowed
	}
	if len(dangerous) == 0 { // pickle-dangerous already says it all
		c.Add(findings.Finding{Rule: "models.pickle", Severity: sev, Path: a.Path, Message: msg,
			Fix:  "prefer .safetensors/GGUF; otherwise torch.load(weights_only=True) inside the sandbox",
			Refs: []string{"https://pytorch.org/docs/stable/generated/torch.load.html"}})
	}
	if fa.partial != "" {
		ps := findings.SevWarn
		if pol.pickleSev() == findings.SevFail && a.Allowed == "" {
			ps = findings.SevFail
		} else if a.Allowed != "" {
			ps = findings.SevInfo
		}
		c.Add(findings.Finding{Rule: "models.pickle-incomplete", Severity: ps, Path: a.Path,
			Message: "opcode scan incomplete (" + fa.partial + "); imports after this point were not checked",
			Fix:     "scan it with picklescan/modelscan in the sandbox"})
	}
}

func list(s []string, n int) string {
	if len(s) > n {
		return strings.Join(s[:n], ", ") + fmt.Sprintf(" and %d more", len(s)-n)
	}
	return strings.Join(s, ", ")
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func judgeStore(c *findings.Collector, s *storeScan, results []result, jobs []job, verify bool) {
	for _, is := range s.issues {
		c.Add(findings.Finding{Rule: is.rule, Severity: is.sev, Path: is.path, Message: is.msg, Fix: is.fix})
	}
	referenced := map[string]bool{}
	variants := map[string][]string{}
	weights := map[string]bool{"model": true, "projector": true, "adapter": true, "draft": true}
	for _, r := range s.refs {
		referenced[r.digest] = true
		info, ok := s.blobs[r.digest]
		if !ok {
			switch {
			case r.kind == "variant":
				variants[r.model] = appendUniq(variants[r.model], or(r.variant, short(r.digest)))
			default:
				sev := findings.SevWarn
				if weights[r.kind] {
					sev = findings.SevFail
				}
				c.Add(findings.Finding{Rule: "ollama.blob-missing", Severity: sev, Path: blobPath(s.store.Dir, r.digest),
					Message: fmt.Sprintf("%s: %s layer blob is missing", or(r.model, "?"), r.kind), Fix: "ollama pull " + r.model})
			}
			continue
		}
		if r.size >= 0 && info.Size() != r.size {
			c.Add(findings.Finding{Rule: "ollama.blob-size", Severity: findings.SevFail, Path: blobPath(s.store.Dir, r.digest),
				Message: fmt.Sprintf("%s: %s blob is %d bytes, manifest says %d", r.model, r.kind, info.Size(), r.size), Fix: "ollama pull " + r.model})
		}
	}
	for m, v := range variants {
		c.Add(findings.Finding{Rule: "ollama.variant-not-pulled", Severity: findings.SevInfo, Path: m,
			Message: "manifest list variants not present locally: " + strings.Join(v, ", ")})
	}
	var orphans []string
	for h, info := range s.blobs {
		if !referenced[h] {
			orphans = append(orphans, "sha256-"+h)
			s.store.OrphanBytes += info.Size()
		}
	}
	sort.Strings(orphans)
	s.store.Orphans = orphans
	if len(orphans) > 0 {
		c.Add(findings.Finding{Rule: "ollama.orphan-blobs", Severity: findings.SevInfo, Path: filepath.Join(s.store.Dir, "blobs"),
			Message: fmt.Sprintf("%d blob(s) (%s) not referenced by any manifest", len(orphans), human(s.store.OrphanBytes)),
			Fix:     "Ollama prunes unreferenced blobs on start unless OLLAMA_NOPRUNE is set"})
	}
	if len(s.store.Partial) > 0 {
		c.Add(findings.Finding{Rule: "ollama.partial", Severity: findings.SevInfo, Path: filepath.Join(s.store.Dir, "blobs"),
			Message: fmt.Sprintf("%d incomplete download(s)", len(s.store.Partial))})
	}
	for _, m := range s.store.Models {
		if m.Registry != "" && !strings.Contains(m.Name, m.Registry) {
			continue
		}
		if m.Registry != "" {
			c.Add(findings.Finding{Rule: "ollama.third-party", Severity: findings.SevInfo, Path: m.Manifest,
				Message: fmt.Sprintf("%s comes from %s, not the Ollama library", m.Name, m.Registry)})
		}
	}
	if verify { // weights were hashed as artifacts; hash the small metadata blobs here
		scanned := map[string]bool{}
		for _, j := range jobs {
			scanned[j.path] = true
		}
		done := map[string]bool{}
		for _, r := range s.refs {
			bp := blobPath(s.store.Dir, r.digest)
			if _, ok := s.blobs[r.digest]; !ok || scanned[bp] || done[bp] {
				continue
			}
			done[bp] = true
			h, err := hashFile(bp)
			if err != nil {
				c.Add(findings.Finding{Rule: "ollama.store-unreadable", Severity: findings.SevWarn, Path: bp, Message: errText(err)})
			} else if h != r.digest {
				c.Add(findings.Finding{Rule: "ollama.blob-digest", Severity: findings.SevFail, Path: bp,
					Message: fmt.Sprintf("%s: %s blob content hashes to %s, not its content-addressed name", or(r.model, "?"), r.kind, short(h)), Fix: "ollama pull " + r.model})
			}
		}
	}
	if !verify {
		c.Add(findings.Finding{Rule: "ollama.digest-unverified", Severity: findings.SevInfo, Path: s.store.Dir,
			Message: fmt.Sprintf("%d blobs (%s) were not re-hashed; their sha256-<digest> names are trusted", s.store.Blobs, human(s.store.BlobBytes)),
			Fix:     "run with --verify-blobs (reads every byte)"})
	}
}

func judgeAPI(c *findings.Collector, or *OllamaReport, stores []*storeScan) {
	if len(or.APIModels) == 0 {
		return
	}
	if len(stores) == 0 {
		c.Add(findings.Finding{Rule: "ollama.store-not-found", Severity: findings.SevInfo, Path: or.URL,
			Message: fmt.Sprintf("the API lists %d model(s) but no readable model store was found, so their blobs were not checked", len(or.APIModels)),
			Fix:     "set [models.ollama] models_dirs (for Docker, the host path of the volume mounted at /root/.ollama, plus /models)"})
		return
	}
	var missing []string
	for i := range or.APIModels {
		m := &or.APIModels[i]
		for _, s := range stores {
			_, blob := s.blobs[m.Digest]
			named := false
			for _, sm := range s.store.Models {
				if sm.Name == m.Name || sm.Name == strings.TrimSuffix(m.Name, ":latest") || sm.Name+":latest" == m.Name {
					named = true
				}
			}
			if blob || named {
				m.InStore = s.store.Dir
				break
			}
		}
		if m.InStore == "" {
			missing = append(missing, m.Name)
		}
	}
	if len(missing) > 0 {
		c.Add(findings.Finding{Rule: "ollama.api-unmatched", Severity: findings.SevWarn, Path: or.URL,
			Message: fmt.Sprintf("%d model(s) served by the API were not found in the scanned store(s): %s", len(missing), list(missing, 8)),
			Fix:     "add the serving instance's store to [models.ollama] models_dirs"})
	}
}

func keyPerms(c *findings.Collector, store string) {
	for _, k := range []string{filepath.Join(filepath.Dir(store), "id_ed25519"), filepath.Join(store, "..", "..", "id_ed25519")} {
		st, err := os.Lstat(filepath.Clean(k))
		if err != nil {
			continue
		}
		if st.Mode().Perm()&0o077 != 0 {
			c.Add(findings.Finding{Rule: "ollama.key-perms", Severity: findings.SevWarn, Path: filepath.Clean(k),
				Message: fmt.Sprintf("Ollama identity key has mode %04o (stat only; not read)", st.Mode().Perm()), Fix: "chmod 600"})
		}
		return
	}
}

func human(n int64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(u), 0
	for m := n / u; m >= u; m /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// Human formats a byte count (exported for the CLI).
func Human(n int64) string { return human(n) }
