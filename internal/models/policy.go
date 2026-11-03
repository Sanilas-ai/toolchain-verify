package models

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

// Policy is the [models] manifest section.
type Policy struct {
	// Roots are files or directories scanned for model artifacts ("~" is
	// expanded). Command-line paths are added to these.
	Roots   []string `toml:"roots"`
	Exclude []string `toml:"exclude"`
	// MaxDepth bounds the walk below each root (default 8).
	MaxDepth int `toml:"max_depth"`
	// Pickle is the severity for pickle-based artifacts whose imports are
	// all on the built-in safe list: "fail", "warn" (default) or "info".
	// Dangerous imports (os.system, builtins.eval, ...) always fail.
	Pickle string `toml:"pickle"`
	// UnknownImport is the severity for imports that are neither known
	// safe nor known dangerous (default "warn").
	UnknownImport string `toml:"unknown_import"`
	// Trusted are path globs ("/**" = subtree) whose pickle files are
	// reported as info (your own checkpoints). Imports are still checked.
	Trusted []string `toml:"trusted"`
	// Hash computes SHA-256 of every artifact found under Roots
	// (default true). Ollama blobs are content-addressed; see
	// [models.ollama] verify_blobs.
	Hash *bool `toml:"hash"`
	// External controls picklescan/modelscan: "auto" (default: use when on
	// PATH, warn when missing and pickle files exist), "require", "off".
	External       string   `toml:"external"`
	Scanners       []string `toml:"scanners"`        // default ["picklescan", "modelscan"]
	ScannerTimeout string   `toml:"scanner_timeout"` // default "120s"
	// Allow lists reviewed artifacts. With a literal path it is also a pin:
	// a different digest at that path fails.
	Allow  []Allow  `toml:"allow"`
	Ignore []string `toml:"ignore"`
	Ollama *Ollama  `toml:"ollama"`

	timeout time.Duration
}

// Allow is one reviewed artifact.
type Allow struct {
	SHA256 string `toml:"sha256"`
	Path   string `toml:"path"` // optional glob; a literal path pins the digest
	Note   string `toml:"note"`
}

// Ollama configures the Ollama report.
type Ollama struct {
	// Enabled (default true) reports on the Ollama API and model stores.
	Enabled *bool `toml:"enabled"`
	// URL of the Ollama API (default http://127.0.0.1:11434, or
	// $OLLAMA_HOST); only GET /api/version and /api/tags are used.
	URL string `toml:"url"`
	// API (default true) queries URL.
	API *bool `toml:"api"`
	// ModelsDirs are Ollama model stores (the directory that holds blobs/
	// and manifests/). Default: $OLLAMA_MODELS, ~/.ollama/models,
	// /usr/share/ollama/.ollama/models, /var/lib/ollama/.ollama/models.
	ModelsDirs []string `toml:"models_dirs"`
	// VerifyBlobs re-hashes every referenced blob and compares it with its
	// sha256-<digest> name (reads every byte; slow for large stores).
	VerifyBlobs bool `toml:"verify_blobs"`
	// Registries considered first-party (default registry.ollama.ai,
	// ollama.com); models from others are reported as info.
	Registries []string `toml:"registries"`
}

var hexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

func validSev(s string) bool {
	return s == "" || s == findings.SevFail || s == findings.SevWarn || s == findings.SevInfo
}

// Validate checks the policy and fills defaults that need parsing.
func (p *Policy) Validate() error {
	if p == nil {
		return nil
	}
	if !validSev(p.Pickle) {
		return fmt.Errorf("models.pickle: want fail, warn or info, got %q", p.Pickle)
	}
	if !validSev(p.UnknownImport) {
		return fmt.Errorf("models.unknown_import: want fail, warn or info, got %q", p.UnknownImport)
	}
	switch p.External {
	case "", "auto", "require", "off":
	default:
		return fmt.Errorf("models.external: want auto, require or off, got %q", p.External)
	}
	if p.MaxDepth < 0 {
		return fmt.Errorf("models.max_depth must be >= 0")
	}
	if p.ScannerTimeout != "" {
		d, err := time.ParseDuration(p.ScannerTimeout)
		if err != nil || d <= 0 {
			return fmt.Errorf("models.scanner_timeout: invalid duration %q", p.ScannerTimeout)
		}
		p.timeout = d
	}
	for i := range p.Allow {
		a := &p.Allow[i]
		a.SHA256 = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(a.SHA256, "sha256:")))
		if !hexRe.MatchString(a.SHA256) {
			return fmt.Errorf("models.allow #%d: sha256 must be 64 hex characters", i+1)
		}
		if a.Path != "" {
			if _, err := filepath.Match(expandHome(a.Path), ""); err != nil {
				return fmt.Errorf("models.allow #%d: bad path glob %q", i+1, a.Path)
			}
		}
	}
	for _, g := range p.Trusted {
		if _, err := filepath.Match(expandHome(g), ""); err != nil {
			return fmt.Errorf("models.trusted: bad glob %q", g)
		}
	}
	if o := p.Ollama; o != nil && o.URL != "" {
		u, err := url.Parse(o.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("models.ollama.url: want http(s)://host:port, got %q", o.URL)
		}
		if u.User != nil {
			return fmt.Errorf("models.ollama.url must not contain credentials")
		}
	}
	return nil
}

func (p *Policy) pickleSev() string  { return or(p.Pickle, findings.SevWarn) }
func (p *Policy) unknownSev() string { return or(p.UnknownImport, findings.SevWarn) }
func (p *Policy) external() string   { return or(p.External, "auto") }
func (p *Policy) hash() bool         { return p.Hash == nil || *p.Hash }
func (p *Policy) maxDepth() int {
	if p.MaxDepth == 0 {
		return 8
	}
	return p.MaxDepth
}

func (p *Policy) scanners() []string {
	if len(p.Scanners) == 0 {
		return []string{"picklescan", "modelscan"}
	}
	return p.Scanners
}

func (p *Policy) scannerTimeout() time.Duration {
	if p.timeout > 0 {
		return p.timeout
	}
	if d, err := time.ParseDuration(p.ScannerTimeout); err == nil && d > 0 {
		return d
	}
	return 120 * time.Second
}

func (o *Ollama) enabled() bool { return o == nil || o.Enabled == nil || *o.Enabled }
func (o *Ollama) api() bool     { return o == nil || o.API == nil || *o.API }

func (o *Ollama) url(getenv func(string) string) string {
	if o != nil && o.URL != "" {
		return strings.TrimRight(o.URL, "/")
	}
	if h := strings.TrimSpace(getenv("OLLAMA_HOST")); h != "" {
		if !strings.Contains(h, "://") {
			h = "http://" + h
		}
		if u, err := url.Parse(h); err == nil && u.Host != "" && u.User == nil {
			host := u.Hostname()
			if host == "0.0.0.0" || host == "::" || host == "" {
				host = "127.0.0.1"
			}
			port := u.Port()
			if port == "" {
				port = "11434"
			}
			u.Host = joinHostPort(host, port)
			u.Path = strings.TrimRight(u.Path, "/")
			return u.String()
		}
	}
	return "http://127.0.0.1:11434"
}

func joinHostPort(h, p string) string {
	if strings.Contains(h, ":") {
		return "[" + h + "]:" + p
	}
	return h + ":" + p
}

func (o *Ollama) registries() []string {
	if o == nil || len(o.Registries) == 0 {
		return []string{"registry.ollama.ai", "ollama.com"}
	}
	return o.Registries
}

func or(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

// matchGlob matches a path against a glob; a "/**" suffix matches a subtree.
func matchGlob(glob, p string) bool {
	glob = expandHome(glob)
	if ok, _ := filepath.Match(glob, p); ok {
		return true
	}
	if sub, ok := strings.CutSuffix(glob, "/**"); ok {
		sub = filepath.Clean(sub)
		p = filepath.Clean(p)
		return p == sub || strings.HasPrefix(p, sub+string(filepath.Separator))
	}
	return false
}

func isLiteral(glob string) bool { return !strings.ContainsAny(glob, "*?[") }
