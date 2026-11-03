package models

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

func TestRunPaths(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "evil.pkl"), pickleOsSystem)
	write(t, filepath.Join(dir, "safe.pt"), zipFile(t, map[string][]byte{"archive/data.pkl": pickleTorchSafe}))
	write(t, filepath.Join(dir, "custom.pth"), pickleUnknown)
	write(t, filepath.Join(dir, "sub", "model.safetensors"), safetensors(t, map[string]any{"w": map[string]any{"dtype": "U8", "shape": []int{2}, "data_offsets": []int{0, 2}}}, []byte{1, 2}))
	write(t, filepath.Join(dir, "broken.safetensors"), safetensors(t, map[string]any{"w": map[string]any{"dtype": "F32", "shape": []int{9}, "data_offsets": []int{0, 36}}}, []byte{1}))
	write(t, filepath.Join(dir, "obj.npy"), npy("'|O'", pickleOsSystem))
	write(t, filepath.Join(dir, "arr.npz"), zipFile(t, map[string][]byte{"a.npy": npy("'<f4'", make([]byte, 8))}))
	write(t, filepath.Join(dir, "m.keras"), zipFile(t, map[string][]byte{"config.json": []byte(`{"class_name": "Lambda", "config": {}}`)}))
	write(t, filepath.Join(dir, "est.joblib"), gz(pickleProto0))
	write(t, filepath.Join(dir, "evil.gguf"), gguf([]ggufKV{{"tokenizer.chat_template", "{{ cycler.__init__.__globals__.os.popen('id').read() }}"}}, nil, 0, 0))
	write(t, filepath.Join(dir, "notes.txt"), []byte("not a model"))
	write(t, filepath.Join(dir, ".git", "x.pkl"), pickleOsSystem)

	rep := scan(t, nil, dir)
	if rep.OK {
		t.Fatalf("expected failure:\n%s", dump(rep))
	}
	for _, w := range []struct{ rule, path, sev string }{
		{"models.pickle-dangerous", "evil.pkl", findings.SevFail},
		{"models.pickle-dangerous", "obj.npy", findings.SevFail},
		{"models.pickle-dangerous", "est.joblib", findings.SevFail},
		{"models.pickle", "safe.pt", findings.SevWarn},
		{"models.pickle-unknown-import", "custom.pth", findings.SevWarn},
		{"models.safetensors-malformed", "broken.safetensors", findings.SevFail},
		{"models.keras-lambda", "m.keras", findings.SevWarn},
		{"models.gguf-template", "evil.gguf", findings.SevFail},
		{"models.scanner-missing", "", findings.SevWarn},
	} {
		f := find(rep, w.rule, w.path)
		if f == nil {
			t.Errorf("missing %s on %s\n%s", w.rule, w.path, dump(rep))
		} else if f.Severity != w.sev {
			t.Errorf("%s on %s: severity %s, want %s", w.rule, w.path, f.Severity, w.sev)
		}
	}
	for _, clean := range []string{"model.safetensors", "arr.npz"} {
		for _, f := range rep.Findings {
			if strings.HasSuffix(f.Path, clean) {
				t.Errorf("clean file flagged: %s %s", f.Rule, f.Message)
			}
		}
	}
	if artifact(rep, "notes.txt") != nil || len(rep.Artifacts) != 10 {
		t.Errorf("artifacts: %d (non-models or .git included?)", len(rep.Artifacts))
	}
	a := artifact(rep, "model.safetensors")
	if a == nil || a.SHA256 != sum([]byte(safetensors(t, map[string]any{"w": map[string]any{"dtype": "U8", "shape": []int{2}, "data_offsets": []int{0, 2}}}, []byte{1, 2}))) || a.Size == 0 {
		t.Errorf("hash/size: %+v", a)
	}
}

func TestPolicyAllowTrustedPin(t *testing.T) {
	dir := t.TempDir()
	safe := write(t, filepath.Join(dir, "ckpt", "mine.pt"), pickleTorchSafe)
	other := write(t, filepath.Join(dir, "reviewed.pkl"), pickleData)
	pinned := write(t, filepath.Join(dir, "pinned.pkl"), pickleData)
	pol := &Policy{
		Pickle:  "fail",
		Trusted: []string{filepath.Join(dir, "ckpt") + "/**"},
		Allow: []Allow{
			{SHA256: sum(pickleData), Note: "reviewed"},
			{SHA256: strings.Repeat("0", 64), Path: pinned},
		},
	}
	rep := scan(t, pol, dir)
	if f := find(rep, "models.pickle", safe); f == nil || f.Severity != findings.SevInfo {
		t.Errorf("trusted: %+v", f)
	}
	if f := find(rep, "models.pickle", other); f == nil || f.Severity != findings.SevInfo {
		t.Errorf("allowlisted: %+v", f)
	}
	if f := find(rep, "models.digest-mismatch", pinned); f == nil || f.Severity != findings.SevFail {
		t.Errorf("pin mismatch:\n%s", dump(rep))
	}
	// dangerous imports fail even when trusted
	write(t, filepath.Join(dir, "ckpt", "evil.pt"), pickleOsSystem)
	if f := find(scan(t, pol, dir), "models.pickle-dangerous", "evil.pt"); f == nil || f.Severity != findings.SevFail {
		t.Error("trusted dangerous pickle not failed")
	}
}

func TestHFBlobMismatch(t *testing.T) {
	dir := t.TempDir()
	good := write(t, filepath.Join(dir, "blobs", sum(pickleData)), pickleData)
	bad := write(t, filepath.Join(dir, "blobs", strings.Repeat("a", 64)), pickleData)
	snap := filepath.Join(dir, "snapshots", "rev")
	os.MkdirAll(snap, 0o755)
	os.Symlink(good, filepath.Join(snap, "good.bin"))
	os.Symlink(bad, filepath.Join(snap, "bad.bin"))
	rep := scan(t, nil, snap)
	if find(rep, "models.digest-mismatch", "bad.bin") == nil || find(rep, "models.digest-mismatch", "good.bin") != nil {
		t.Errorf("HF blob digests:\n%s", dump(rep))
	}
}

func TestRefuseRootAndValidate(t *testing.T) {
	if _, err := Run(&Policy{}, Options{Paths: []string{"/"}, NoOllama: true}); !errors.Is(err, ErrRefused) {
		t.Errorf("/ not refused: %v", err)
	}
	for _, p := range []Policy{
		{Pickle: "loud"},
		{External: "maybe"},
		{Allow: []Allow{{SHA256: "abc"}}},
		{ScannerTimeout: "soon"},
		{Ollama: &Ollama{URL: "http://user:pw@127.0.0.1:11434"}},
		{Ollama: &Ollama{URL: "file:///etc/passwd"}},
	} {
		if err := p.Validate(); err == nil {
			t.Errorf("accepted %+v", p)
		}
	}
	if err := (&Policy{Pickle: "info", Allow: []Allow{{SHA256: strings.Repeat("f", 64)}}}).Validate(); err != nil {
		t.Error(err)
	}
}

func TestExternalScanner(t *testing.T) {
	dir := t.TempDir()
	evil := write(t, filepath.Join(dir, "m", "x.pkl"), pickleData)
	bin := filepath.Join(dir, "bin")
	// fake picklescan: report issues for every file (exit 1); log argv
	write(t, filepath.Join(bin, "picklescan"), []byte("#!/bin/sh\necho \"$@\" >> \""+filepath.Join(dir, "argv")+"\"\necho 'Dangerous import detected'\nexit 1\n"))
	os.Chmod(filepath.Join(bin, "picklescan"), 0o755)
	look := func(n string) (string, error) {
		p := filepath.Join(bin, n)
		if _, err := os.Stat(p); err != nil {
			return "", os.ErrNotExist
		}
		return p, nil
	}
	rep, err := Run(&Policy{}, Options{Paths: []string{filepath.Dir(evil)}, NoOllama: true, Getenv: noEnv, LookPath: look})
	if err != nil {
		t.Fatal(err)
	}
	if f := find(rep, "models.scanner", "x.pkl"); f == nil || f.Severity != findings.SevFail {
		t.Fatalf("scanner issues not reported:\n%s", dump(rep))
	}
	if argv, _ := os.ReadFile(filepath.Join(dir, "argv")); !strings.Contains(string(argv), "--path "+evil) {
		t.Errorf("argv %q", argv)
	}
	if find(rep, "models.scanner-missing", "") != nil {
		t.Error("scanner-missing despite picklescan")
	}
	// require without scanners fails
	rep, _ = Run(&Policy{External: "require"}, Options{Paths: []string{filepath.Dir(evil)}, NoOllama: true, Getenv: noEnv, LookPath: noScanners})
	if f := find(rep, "models.scanner-missing", ""); f == nil || f.Severity != findings.SevFail {
		t.Errorf("require:\n%s", dump(rep))
	}
	// off: no warning
	rep, _ = Run(&Policy{}, Options{Paths: []string{filepath.Dir(evil)}, NoOllama: true, External: "off", Getenv: noEnv, LookPath: noScanners})
	if find(rep, "models.scanner-missing", "") != nil {
		t.Error("external=off still warns")
	}
}

// ---- Ollama ----

type fakeStore struct {
	t   *testing.T
	dir string
}

func (s fakeStore) blob(data []byte) string {
	h := sum(data)
	write(s.t, filepath.Join(s.dir, "blobs", "sha256-"+h), data)
	return h
}

func layer(typ, h string, size int) map[string]any {
	return map[string]any{"mediaType": "application/vnd.ollama.image." + typ, "digest": "sha256:" + h, "size": size}
}

func manifestJSON(t *testing.T, cfg string, layers ...map[string]any) []byte {
	b, err := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
		"config": map[string]any{"mediaType": "application/vnd.docker.container.image.v1+json", "digest": "sha256:" + cfg, "size": 2},
		"layers": layers})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOllamaStore(t *testing.T) {
	dir := t.TempDir()
	s := fakeStore{t, dir}
	weights := gguf([]ggufKV{{"general.architecture", "llama"}}, []ggufTensor{{"a", []uint64{8}, 0, 0}}, 32, 0)
	cfg := s.blob([]byte("{}"))
	w := s.blob(weights)
	tmpl := s.blob([]byte("{{ .Prompt }}"))
	// good v1 manifest
	write(t, filepath.Join(dir, "manifests", "registry.ollama.ai", "library", "good", "latest"),
		manifestJSON(t, cfg, layer("model", w, len(weights)), layer("template", tmpl, 13)))
	// missing weights + wrong template size
	write(t, filepath.Join(dir, "manifests", "registry.ollama.ai", "library", "broken", "1b"),
		manifestJSON(t, cfg, layer("model", strings.Repeat("b", 64), 100), layer("template", tmpl, 99)))
	// third-party registry
	write(t, filepath.Join(dir, "manifests", "hf.co", "someone", "repo", "q4"), manifestJSON(t, cfg, layer("model", w, len(weights))))
	// v2: manifest list with a pulled child and a missing variant, linked by symlink
	child := s.blob(manifestJSON(t, cfg, layer("model", w, len(weights))))
	list, _ := json.Marshal(map[string]any{"mediaType": "application/vnd.ollama.manifest.list.v2+json", "manifests": []map[string]any{
		{"digest": "sha256:" + child, "runner": "llama", "format": "gguf"},
		{"digest": "sha256:" + strings.Repeat("c", 64), "runner": "mlx", "format": "safetensors"},
	}})
	lh := s.blob(list)
	v2 := filepath.Join(dir, "manifests-v2", "registry.ollama.ai", "library", "multi", "latest")
	os.MkdirAll(filepath.Dir(v2), 0o755)
	os.Symlink(filepath.Join(dir, "blobs", "sha256-"+lh), v2)
	// escape symlink
	outside := write(t, filepath.Join(t.TempDir(), "evil"), []byte("{}"))
	esc := filepath.Join(dir, "manifests-v2", "registry.ollama.ai", "library", "escape", "latest")
	os.MkdirAll(filepath.Dir(esc), 0o755)
	os.Symlink(outside, esc)
	// orphan, partial, digest mismatch (name says one thing, content another)
	s.blob([]byte("orphan"))
	write(t, filepath.Join(dir, "blobs", "sha256-"+strings.Repeat("d", 64)+"-partial"), []byte("x"))

	pol := &Policy{Ollama: &Ollama{ModelsDirs: []string{dir}}}
	rep, err := Run(pol, Options{NoAPI: true, Getenv: noEnv, LookPath: noScanners})
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []struct{ rule, path, sev string }{
		{"ollama.blob-missing", strings.Repeat("b", 64), findings.SevFail},
		{"ollama.blob-size", tmpl, findings.SevFail},
		{"ollama.variant-not-pulled", "multi", findings.SevInfo},
		{"ollama.manifest-escape", "escape", findings.SevFail},
		{"ollama.orphan-blobs", "blobs", findings.SevInfo},
		{"ollama.partial", "blobs", findings.SevInfo},
		{"ollama.third-party", "hf.co", findings.SevInfo},
		{"ollama.digest-unverified", dir, findings.SevInfo},
	} {
		f := find(rep, w.rule, w.path)
		if f == nil {
			t.Errorf("missing %s on %s\n%s", w.rule, w.path, dump(rep))
		} else if f.Severity != w.sev {
			t.Errorf("%s: severity %s, want %s", w.rule, f.Severity, w.sev)
		}
	}
	if find(rep, "ollama.third-party", "library/good") != nil {
		t.Error("library model flagged as third-party")
	}
	if len(rep.Ollama.Stores) != 1 || len(rep.Ollama.Stores[0].Orphans) != 1 {
		t.Errorf("store report: %+v", rep.Ollama.Stores)
	}
	// weights blob is scanned as GGUF and attributed to its models
	var ga *Artifact
	for i, a := range rep.Artifacts {
		if strings.HasSuffix(a.Path, w) {
			ga = &rep.Artifacts[i]
		}
	}
	if ga == nil || ga.Format != FmtGGUF || ga.Source != "ollama" || len(ga.Models) < 2 {
		t.Errorf("weights artifact: %+v", ga)
	}

	// --verify-blobs: corrupt the template blob content under its name
	os.WriteFile(filepath.Join(dir, "blobs", "sha256-"+tmpl), []byte("{{ .Prompt }}!"), 0o644)
	rep, _ = Run(pol, Options{NoAPI: true, VerifyBlobs: true, Getenv: noEnv, LookPath: noScanners})
	if find(rep, "ollama.blob-digest", tmpl) == nil {
		t.Errorf("verify did not catch corrupted blob\n%s", dump(rep))
	}
	if find(rep, "ollama.digest-unverified", dir) != nil {
		t.Error("digest-unverified with --verify-blobs")
	}
}

func TestOllamaAPI(t *testing.T) {
	dir := t.TempDir()
	s := fakeStore{t, dir}
	cfg := s.blob([]byte("{}"))
	m := manifestJSON(t, cfg)
	write(t, filepath.Join(dir, "manifests", "registry.ollama.ai", "library", "known", "latest"), m)
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/api/version":
			fmt.Fprint(w, `{"version":"0.0.1-test"}`)
		case "/api/tags":
			fmt.Fprintf(w, `{"models":[{"name":"known:latest","digest":"%s","size":2},{"name":"ghost:7b","digest":"%s","size":9}]}`, sum(m), strings.Repeat("e", 64))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	rep, err := Run(&Policy{Ollama: &Ollama{URL: srv.URL, ModelsDirs: []string{dir}}}, Options{Getenv: noEnv, LookPath: noScanners})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Ollama.Version != "0.0.1-test" || len(rep.Ollama.APIModels) != 2 {
		t.Fatalf("api: %+v", rep.Ollama)
	}
	f := find(rep, "ollama.api-unmatched", "")
	if f == nil || !strings.Contains(f.Message, "ghost:7b") || strings.Contains(f.Message, "known") {
		t.Errorf("api-unmatched:\n%s", dump(rep))
	}
	for _, p := range paths {
		if !strings.HasPrefix(p, "GET /api/version") && !strings.HasPrefix(p, "GET /api/tags") {
			t.Errorf("unexpected request %s", p)
		}
	}
	// unreachable API is a warning, not a crash
	srv.Close()
	rep, _ = Run(&Policy{Ollama: &Ollama{URL: srv.URL, ModelsDirs: []string{dir}}}, Options{Getenv: noEnv, LookPath: noScanners})
	if find(rep, "ollama.api-unreachable", "") == nil {
		t.Errorf("unreachable:\n%s", dump(rep))
	}
}

func TestOllamaHostEnv(t *testing.T) {
	env := func(k string) string {
		if k == "OLLAMA_HOST" {
			return "0.0.0.0:8080"
		}
		return ""
	}
	if u := (&Ollama{}).url(env); u != "http://127.0.0.1:8080" {
		t.Errorf("OLLAMA_HOST: %s", u)
	}
	if u := (*Ollama)(nil).url(noEnv); u != "http://127.0.0.1:11434" {
		t.Errorf("default: %s", u)
	}
}
