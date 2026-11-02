package agent

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

var pickleExts = map[string]bool{".pkl": true, ".pickle": true, ".pt": true, ".pth": true, ".ckpt": true, ".joblib": true}

// checkModelFile flags pickle-based model files in untrusted locations:
// loading them (torch.load without weights_only, pickle.load, joblib.load)
// executes arbitrary code.
func checkModelFile(c *collector, p string, d fs.DirEntry) {
	ext := strings.ToLower(filepath.Ext(p))
	if !pickleExts[ext] {
		return
	}
	c.add(Finding{Rule: "supply.pickle-model", Severity: SevWarn, Path: p,
		Message: "pickle-based model/data file in an untrusted location; loading it with pickle/torch.load(weights_only=False)/joblib executes embedded code",
		Fix:     "prefer .safetensors / ONNX from a verified source; if you must load it, use torch.load(weights_only=True) in a sandbox",
		Refs:    []string{"https://docs.python.org/3/library/pickle.html", "https://pytorch.org/docs/stable/generated/torch.load.html"}})
}

// legitPth are startup hooks shipped by common tooling.
var legitPth = []string{"distutils-precedence.pth", "_virtualenv.pth", "easy-install.pth", "setuptools.pth", "matplotlib-", "-nspkg.pth", "__editable__", "_distutils_hack", "coverage", "pywin32.pth", "a1_coverage.pth"}

// checkPth flags .pth files that execute code at every interpreter start
// (lines beginning with "import"), a known persistence/supply-chain trick.
func checkPth(c *collector, p string) {
	base := filepath.Base(p)
	for _, l := range legitPth {
		if strings.Contains(base, l) {
			return
		}
	}
	f, err := os.Open(p)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, 1<<20))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "import ") || strings.HasPrefix(line, "import\t") {
			c.add(Finding{Rule: "supply.pth-exec", Severity: SevWarn, Path: p,
				Message: "site-packages .pth file runs code at every Python start (line begins with \"import\"); legitimate for some packages, also abused by malicious ones",
				Fix:     "check which package installed it (pip show -f / RECORD files) and remove it if unknown",
				Refs:    []string{"https://docs.python.org/3/library/site.html"}})
			return
		}
	}
}

// checkSupplyChain inspects package index configuration (never token files).
func checkSupplyChain(r *resolved, c *collector) {
	for _, k := range []string{"PIP_EXTRA_INDEX_URL", "UV_EXTRA_INDEX_URL"} {
		if v := r.getenv(k); v != "" {
			extraIndex(c, "$"+k, v)
		}
	}
	for _, k := range []string{"PIP_INDEX_URL", "UV_INDEX_URL", "UV_DEFAULT_INDEX", "NPM_CONFIG_REGISTRY", "npm_config_registry", "YARN_NPM_REGISTRY_SERVER"} {
		if v := r.getenv(k); v != "" {
			cleartextIndex(c, "$"+k, v)
		}
	}
	if v := r.getenv("PIP_TRUSTED_HOST"); v != "" {
		c.add(Finding{Rule: "supply.trusted-host", Severity: SevWarn, Path: "$PIP_TRUSTED_HOST", Message: "pip TLS verification disabled for: " + v})
	}
	confs := []string{
		filepath.Join(r.home, ".config", "pip", "pip.conf"),
		filepath.Join(r.home, ".pip", "pip.conf"),
		"/etc/pip.conf", "/etc/xdg/pip/pip.conf",
		filepath.Join(r.home, ".config", "uv", "uv.toml"),
	}
	if v := r.getenv("PIP_CONFIG_FILE"); v != "" {
		confs = append(confs, v)
	}
	if v := r.getenv("VIRTUAL_ENV"); v != "" {
		confs = append(confs, filepath.Join(v, "pip.conf"))
	}
	for _, p := range dedupe(confs) {
		if _, bad := r.credentialFileHit(p); bad {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(io.LimitReader(f, 1<<20))
		cont := ""
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			key, val, ok := strings.Cut(line, "=")
			if !ok {
				if cont == "extra" && line != "" && !strings.HasPrefix(line, "[") {
					extraIndex(c, p, line)
				}
				continue
			}
			key = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(key, "_", "-")))
			val = strings.Trim(strings.TrimSpace(val), `"'[]`)
			cont = ""
			switch key {
			case "extra-index-url":
				cont = "extra"
				if val != "" {
					extraIndex(c, p, val)
				}
			case "index-url", "index", "default-index":
				if val != "" {
					cleartextIndex(c, p, val)
				}
			case "trusted-host":
				c.add(Finding{Rule: "supply.trusted-host", Severity: SevWarn, Path: p, Message: "pip TLS verification disabled for: " + val})
			}
		}
		f.Close()
	}
}

func redact(u string) string {
	pu, err := url.Parse(strings.TrimSpace(u))
	if err != nil || pu.Host == "" {
		return "<unparseable>"
	}
	pu.User = nil
	pu.RawQuery = ""
	return pu.String()
}

func extraIndex(c *collector, where, val string) {
	for _, u := range strings.Fields(val) {
		c.add(Finding{Rule: "supply.extra-index", Severity: SevWarn, Path: where,
			Message: fmt.Sprintf("extra package index %s: pip/uv may install a same-named package from either index (dependency confusion)", redact(u)),
			Fix:     "use a single index that proxies PyPI, or uv's explicit per-package index pinning"})
		cleartextIndex(c, where, u)
	}
}

func cleartextIndex(c *collector, where, val string) {
	pu, err := url.Parse(strings.TrimSpace(val))
	if err != nil {
		return
	}
	if pu.Scheme == "http" && !isLoopback(pu.Hostname()) {
		c.add(Finding{Rule: "supply.cleartext-index", Severity: SevFail, Path: where,
			Message: fmt.Sprintf("package index over cleartext http: %s; packages can be replaced in transit", redact(val)),
			Fix:     "use https"})
	}
}
