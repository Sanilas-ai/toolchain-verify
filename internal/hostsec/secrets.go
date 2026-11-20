package hostsec

// secrets group (on demand, not part of "all"): finds plaintext API tokens
// and exchange / wallet keys in well-known locations and in environment
// variable names. Files are read to match patterns, but a value is never
// printed: findings carry the path, line, credential kind and a redacted
// form that keeps only the public prefix ("hf_…[37 chars]").
//
// Context (2T threat intel 2026-11-16): the Cursor marketplace breach
// started with a stolen credential; the $6.3B exchange heist started on a
// developer machine that held exchange keys and ran a fake interview repo.

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

// SecretsPolicy is [host.secrets].
type SecretsPolicy struct {
	// ForbidExchangeKeys marks this host as a sandbox / swarm host on which
	// crypto-exchange API keys and wallet keys must never exist: any such
	// key (file or environment) fails as host.exchange-key-forbidden.
	ForbidExchangeKeys bool `toml:"forbid_exchange_keys"`
	// ExtraPaths are additional files or directories to scan ("~/" is
	// expanded for every home directory).
	ExtraPaths []string `toml:"extra_paths"`
}

type tokenPattern struct {
	kind, prefix string
	re           *regexp.Regexp
}

// Value patterns. The prefix is the only part of a match ever shown.
var tokenPatterns = []tokenPattern{
	{"github-token", "github_pat_", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,255}`)},
	{"github-token", "", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,255}\b`)},
	{"huggingface-token", "hf_", regexp.MustCompile(`\bhf_[A-Za-z0-9]{30,}\b`)},
	{"anthropic-api-key", "sk-ant-", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}`)},
	{"openai-api-key", "sk-", regexp.MustCompile(`\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}`)},
	{"google-ai-api-key", "AIza", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"xai-api-key", "xai-", regexp.MustCompile(`\bxai-[A-Za-z0-9]{40,}\b`)},
	{"groq-api-key", "gsk_", regexp.MustCompile(`\bgsk_[A-Za-z0-9]{40,}\b`)},
	{"npm-token", "npm_", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{"pypi-token", "pypi-", regexp.MustCompile(`\bpypi-[A-Za-z0-9_-]{50,}`)},
}

var (
	exchangeNames = `BINANCE|BYBIT|OKX|OKEX|KRAKEN|COINBASE|KUCOIN|BITGET|BITFINEX|BITSTAMP|GATEIO|GATE_IO|HUOBI|HTX|MEXC|BITMEX|DERIBIT|UPBIT|BITHUMB`
	// NAME=value / "name": "value" assignments of exchange API keys.
	exchangeAssignRe = regexp.MustCompile(`(?i)\b([A-Z0-9_]*?(?:` + exchangeNames + `)[A-Z0-9_]*?(?:API_?KEY|API_?SECRET|SECRET(?:_KEY)?|PASSPHRASE|PRIVATE_KEY))["']?\s*[:=]\s*["']?([^\s"'#,;]{8,})`)
	walletAssignRe   = regexp.MustCompile(`(?i)\b([A-Z0-9_]*?(?:MNEMONIC|SEED_PHRASE|WALLET_PRIVATE_KEY|WALLET_KEY|ETH_PRIVATE_KEY|SOL(?:ANA)?_PRIVATE_KEY|BTC_PRIVATE_KEY|PRIVATE_KEY_WALLET))["']?\s*[:=]\s*["']?([^"'#\n]{8,})`)
	exchangeNameRe   = regexp.MustCompile(`(?i)(` + exchangeNames + `)`)
	gitCredRe        = regexp.MustCompile(`^https?://[^:/@\s]+:([^@\s]+)@([^/\s]+)`)
	placeholderRe    = regexp.MustCompile(`(?i)^(\$|<|\{\{)|your[_-]|xxxx|example|changeme|placeholder|replace[_-]?me|dummy|\*\*\*`)
)

// secretEnvNames are environment variables whose presence alone matters
// (the value is never read).
var secretEnvNameRe = regexp.MustCompile(`(?i)(TOKEN|API_?KEY|SECRET|PASSWORD|PASSPHRASE|PRIVATE_KEY|MNEMONIC|SEED_PHRASE|CREDENTIALS?)$`)

// skipConfigDirs are ~/.config subdirectories that hold browser profiles
// and caches (large, binary, and covered by their own encryption).
var skipConfigDirs = map[string]bool{"google-chrome": true, "chromium": true, "BraveSoftware": true, "microsoft-edge": true, "Cache": true,
	"CachedData": true, "Code Cache": true, "GPUCache": true, "Service Worker": true, "IndexedDB": true, "Local Storage": true,
	"Session Storage": true, "blob_storage": true, "WebStorage": true, "logs": true, "CachedExtensionVSIXs": true, "pulse": true}

const (
	secretsMaxFile  = 256 << 10
	secretsMaxFiles = 5000
	configDepth     = 4
)

type secretHit struct {
	at, kind, shown string
	exchange        bool
}

func checkSecrets(e *env, opt Options, p *SecretsPolicy, c *findings.Collector) {
	if p == nil {
		p = &SecretsPolicy{}
	}
	var hits []secretHit
	seen := map[string]bool{}
	budget := secretsMaxFiles
	scanFile := func(f string) {
		if seen[f] || budget <= 0 {
			return
		}
		seen[f] = true
		budget--
		hits = append(hits, scanSecretFile(e, f)...)
	}
	for _, h := range homeDirs(e) {
		for _, f := range []string{".cache/huggingface/token", ".huggingface/token", ".git-credentials", ".config/git/credentials", ".netrc", ".pypirc", ".npmrc"} {
			scanFile(path.Join(h, f))
		}
		for _, pat := range []string{".env*", "*/.env*", "*/*/.env*"} {
			for _, f := range e.glob(path.Join(h, pat)) {
				if isEnvFile(path.Base(f)) {
					scanFile(f)
				}
			}
		}
		walkSecrets(e, path.Join(h, ".config"), configDepth, scanFile)
		for _, x := range p.ExtraPaths {
			x = strings.TrimSpace(x)
			if strings.HasPrefix(x, "~/") {
				x = path.Join(h, x[2:])
			} else if !strings.HasPrefix(x, "/") {
				continue
			}
			walkSecrets(e, x, configDepth, scanFile)
		}
	}
	for _, hit := range hits {
		report := func(rule, sev, msg, fix string) {
			c.Add(findings.Finding{Rule: rule, Severity: sev, Path: hit.at, CWE: cwe("CWE-312", "CWE-522"), Message: msg, Fix: fix,
				Refs: []string{"https://www.bleepingcomputer.com/news/security/cursor-confirms-security-breach-led-to-malicious-claude-code-extension/"}})
		}
		if hit.exchange && p.ForbidExchangeKeys {
			report("host.exchange-key-forbidden", findings.SevFail,
				fmt.Sprintf("%s (%s) on a host marked sandbox/swarm (host.secrets.forbid_exchange_keys); value not shown", hit.kind, hit.shown),
				"move the key off this host (exchange and wallet keys belong only on a dedicated signing machine), then revoke and re-issue it at the exchange")
			continue
		}
		report("host.secret-file", findings.SevWarn,
			fmt.Sprintf("plaintext %s (%s); value not shown", hit.kind, hit.shown),
			"move it to the OS keychain / a secret manager or pass it per command; revoke it if this machine ever ran untrusted code")
	}
	checkSecretEnv(opt.Environ, p, c)
}

func isEnvFile(b string) bool {
	if b != ".env" && !strings.HasPrefix(b, ".env.") {
		return false
	}
	for _, s := range []string{".example", ".sample", ".template", ".dist", ".defaults"} {
		if strings.HasSuffix(b, s) {
			return false
		}
	}
	return true
}

// walkSecrets scans a file, or the regular files of a directory up to depth.
func walkSecrets(e *env, root string, depth int, scan func(string)) {
	st, err := os.Lstat(e.path(root))
	if err != nil {
		return
	}
	if st.Mode().IsRegular() {
		scan(root)
		return
	}
	if !st.IsDir() {
		return
	}
	base := e.path(root)
	_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(base, p)
		if d.IsDir() {
			if p != base && (skipConfigDirs[d.Name()] || strings.Count(rel, string(filepath.Separator)) >= depth-1) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if info, err := d.Info(); err != nil || info.Size() > secretsMaxFile {
			return nil
		}
		scan(path.Join(root, filepath.ToSlash(rel)))
		return nil
	})
}

func scanSecretFile(e *env, f string) []secretHit {
	st, err := os.Lstat(e.path(f))
	if err != nil || !st.Mode().IsRegular() || st.Size() > secretsMaxFile {
		return nil
	}
	b, err := e.read(f)
	if err != nil || bytes.IndexByte(b[:min(len(b), 512)], 0) >= 0 {
		return nil
	}
	var out []secretHit
	base := path.Base(f)
	for i, line := range strings.Split(string(b), "\n") {
		at := fmt.Sprintf("%s:%d", f, i+1)
		if base == ".git-credentials" || (base == "credentials" && strings.HasSuffix(f, "/git/credentials")) {
			if m := gitCredRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil && !placeholderRe.MatchString(m[1]) {
				kind := "git credential for " + m[2]
				if k, pre := classifyToken(m[1]); k != "" {
					kind = k + " (git credential for " + m[2] + ")"
					out = append(out, secretHit{at: at, kind: kind, shown: redact(pre, len(m[1]))})
				} else {
					out = append(out, secretHit{at: at, kind: kind, shown: redact("", len(m[1]))})
				}
				continue
			}
		}
		lineHits := 0
		for _, m := range exchangeAssignRe.FindAllStringSubmatch(line, -1) {
			if placeholderRe.MatchString(m[2]) {
				continue
			}
			ex := strings.ToLower(exchangeNameRe.FindString(m[1]))
			out = append(out, secretHit{at: at, kind: ex + " exchange API key", shown: m[1] + "=" + redact("", len(m[2])), exchange: true})
			lineHits++
		}
		for _, m := range walletAssignRe.FindAllStringSubmatch(line, -1) {
			v := strings.TrimSpace(m[2])
			if placeholderRe.MatchString(v) {
				continue
			}
			out = append(out, secretHit{at: at, kind: "wallet key / seed phrase", shown: m[1] + "=" + redact("", len(v)), exchange: true})
			lineHits++
		}
		if lineHits > 0 {
			continue
		}
		for _, tp := range tokenPatterns {
			if tp.kind == "openai-api-key" && strings.Contains(line, "sk-ant-") {
				continue
			}
			for _, m := range tp.re.FindAllString(line, -1) {
				pre := tp.prefix
				if pre == "" {
					pre = m[:4] // gh?_
				}
				out = append(out, secretHit{at: at, kind: tp.kind, shown: redact(pre, len(m))})
			}
		}
	}
	return out
}

func classifyToken(v string) (kind, prefix string) {
	for _, tp := range tokenPatterns {
		if m := tp.re.FindString(v); m != "" && m == v {
			if tp.prefix == "" {
				return tp.kind, v[:4]
			}
			return tp.kind, tp.prefix
		}
	}
	return "", ""
}

// redact shows only a public prefix and the length.
func redact(prefix string, n int) string {
	if prefix == "" {
		return fmt.Sprintf("<redacted, %d chars>", n)
	}
	return fmt.Sprintf("%s…[%d chars]", prefix, n)
}

// checkSecretEnv reports variable names only.
func checkSecretEnv(environ []string, p *SecretsPolicy, c *findings.Collector) {
	var names, exch []string
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || v == "" {
			continue
		}
		isExch := exchangeNameRe.MatchString(k) && secretEnvNameRe.MatchString(k) || walletAssignRe.MatchString(k+"="+v) && !placeholderRe.MatchString(v)
		if isExch {
			exch = append(exch, k)
			continue
		}
		if kind, _ := classifyToken(v); kind != "" || secretEnvNameRe.MatchString(k) && len(v) >= 16 && !placeholderRe.MatchString(v) {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	sort.Strings(exch)
	if len(exch) > 0 {
		sev, rule := findings.SevWarn, "host.secret-env"
		msg := "exchange / wallet keys exported in this environment (names only): " + strings.Join(exch, ", ")
		if p.ForbidExchangeKeys {
			sev, rule = findings.SevFail, "host.exchange-key-forbidden"
			msg += "; this host is marked sandbox/swarm (host.secrets.forbid_exchange_keys)"
		}
		c.Add(findings.Finding{Rule: rule, Severity: sev, Path: "environment", CWE: cwe("CWE-526"), Message: msg,
			Fix: "unset them and keep exchange / wallet keys only on a dedicated signing machine"})
	}
	if len(names) > 0 {
		c.Add(findings.Finding{Rule: "host.secret-env", Severity: findings.SevInfo, Path: "environment", CWE: cwe("CWE-526"),
			Message: "secrets exported in this environment (names only): " + strings.Join(names, ", ") + "; every child process inherits them",
			Fix:     "pass credentials only to the command that needs them"})
	}
}
