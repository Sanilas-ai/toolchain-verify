package hostsec

// apps group additions (2T threat intel 2026-11-16): Chrome/Chromium and
// PHP version floors, PATH order, version-manager (pyenv/rbenv/nodenv) and
// Homebrew tamper checks, IDE extension auto-update. Read-only.

import (
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

// ---- Chrome / Chromium: CVE-2026-125350 (XML use-after-free, CISA KEV) ----

const chromeFixed = "157.0.8103.50"

var chromeVerRe = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)\.(\d+)`)

// ParseQuad parses a four-part version ("157.0.8103.50"), ignoring any
// epoch, distro suffix or surrounding text.
func ParseQuad(s string) ([4]int, bool) {
	var v [4]int
	if i := strings.IndexByte(s, ':'); i >= 0 && i < 3 {
		s = s[i+1:]
	}
	m := chromeVerRe.FindStringSubmatch(s)
	if m == nil {
		return v, false
	}
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	return v, true
}

func lessQuad(a, b [4]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func checkChrome(e *env, opt Options, dpkg map[string]dpkgPkg, c *findings.Collector) {
	type src struct{ where, ver string }
	var found []src
	if len(opt.ChromeVersion) > 0 {
		found = append(found, src{"google-chrome --version", strings.TrimSpace(string(opt.ChromeVersion))})
	} else {
		for _, n := range []string{"google-chrome-stable", "google-chrome-beta", "google-chrome-unstable", "chromium", "chromium-browser"} {
			if p, ok := dpkg[n]; ok {
				found = append(found, src{"dpkg " + n, p.Version})
			}
		}
		if b, err := e.read("/snap/chromium/current/meta/snap.yaml"); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				if v, ok := strings.CutPrefix(l, "version:"); ok {
					found = append(found, src{"snap chromium", strings.Trim(strings.TrimSpace(v), `"'`)})
				}
			}
		}
	}
	fixed, _ := ParseQuad(chromeFixed)
	for _, s := range found {
		v, ok := ParseQuad(s.ver)
		if !ok {
			continue // e.g. the Ubuntu chromium-browser transitional deb ("2:1snap1")
		}
		if lessQuad(v, fixed) {
			c.Add(findings.Finding{Rule: "host.chrome-cve-2026-125350", Severity: findings.SevFail, Path: s.where, CWE: cwe("CWE-416"),
				Message: fmt.Sprintf("Chrome/Chromium %d.%d.%d.%d < %s: XML use-after-free exploited in the wild (CVE-2026-125350, CISA KEV, due 2026-11-24)", v[0], v[1], v[2], v[3], chromeFixed),
				Fix:     "update Chrome/Chromium to 157.0.8103.50 or later and restart the browser (the old build keeps running until relaunch)",
				Refs: []string{"https://nvd.nist.gov/vuln/detail/CVE-2026-125350", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
					"https://www.bleepingcomputer.com/news/security/google-patches-eighth-chrome-zero-day-exploited-in-attacks-this-year/"}})
		}
	}
}

// ---- PHP: CVE-2026-109618 / CVE-2026-109619 (unauthenticated RCE) ----

// phpFixed are the first fixed patch releases per supported branch
// (2026-10-21). Branches below 8.2 are end of life and have no fix.
var phpFixed = map[[2]int]int{{8, 2}: 35, {8, 3}: 36, {8, 4}: 27, {8, 5}: 12}

var (
	phpVerRe = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)
	phpPkgRe = regexp.MustCompile(`^(?:php(\d\.\d)-(?:cli|fpm|cgi|common)|libapache2-mod-php(\d\.\d))$`)
)

// PHPVulnerable109618 reports whether an upstream PHP version lacks the fix.
func PHPVulnerable109618(maj, min, patch int) bool {
	if maj != 8 {
		return maj < 8
	}
	if fixed, ok := phpFixed[[2]int{maj, min}]; ok {
		return patch < fixed
	}
	return min < 2 // EOL branches; 8.6+ is newer than the fix
}

func checkPHP(e *env, opt Options, dpkg map[string]dpkgPkg, c *findings.Collector) {
	type src struct{ where, ver, pkg string }
	var found []src
	if len(opt.PHPVersion) > 0 {
		found = append(found, src{"php -v", strings.TrimSpace(string(opt.PHPVersion)), ""})
	} else {
		seen := map[string]bool{}
		for name, p := range dpkg {
			m := phpPkgRe.FindStringSubmatch(name)
			if m == nil || strings.Contains(name, ":") {
				continue
			}
			branch := m[1] + m[2]
			if seen[branch] {
				continue
			}
			seen[branch] = true
			found = append(found, src{"dpkg " + name, p.Version, name})
		}
	}
	refs := []string{"https://www.php.net/archive/2026.php", "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w", "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp"}
	for _, s := range found {
		raw := s.ver
		if i := strings.IndexByte(raw, ':'); i >= 0 && i < 3 {
			raw = raw[i+1:]
		}
		m := phpVerRe.FindStringSubmatch(raw)
		if m == nil {
			continue
		}
		maj, _ := strconv.Atoi(m[1])
		min, _ := strconv.Atoi(m[2])
		patch, _ := strconv.Atoi(m[3])
		if !PHPVulnerable109618(maj, min, patch) {
			continue
		}
		if s.pkg != "" {
			cl := "/usr/share/doc/" + s.pkg + "/changelog.Debian.gz"
			if debianChangelogMentions(e, cl, "CVE-2026-109618") {
				c.Add(findings.Finding{Rule: "host.php-cve-2026-109618", Severity: findings.SevInfo, Path: cl, CWE: cwe("CWE-94"),
					Message: fmt.Sprintf("PHP %d.%d.%d is below the upstream fix, but the distro changelog lists CVE-2026-109618 as fixed (backport)", maj, min, patch), Refs: refs})
				continue
			}
		}
		want := "8.2.35 / 8.3.36 / 8.4.27 / 8.5.12"
		if f, ok := phpFixed[[2]int{maj, min}]; ok {
			want = fmt.Sprintf("%d.%d.%d", maj, min, f)
		}
		c.Add(findings.Finding{Rule: "host.php-cve-2026-109618", Severity: findings.SevFail, Path: s.where, CWE: cwe("CWE-94"),
			Message: fmt.Sprintf("PHP %d.%d.%d < %s: unauthenticated remote code execution (CVE-2026-109618, CVE-2026-109619); branches below 8.2 are end of life", maj, min, patch, want),
			Fix:     "upgrade PHP to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later (distro: install the security update that lists the CVEs), or remove it if unused",
			Refs:    refs})
	}
}

// ---- PATH order ----

var systemPathDirs = map[string]bool{"/usr/local/sbin": true, "/usr/local/bin": true, "/usr/sbin": true, "/usr/bin": true, "/sbin": true, "/bin": true}

// privilegedCmds shadowed from a user-writable directory fail.
var privilegedCmds = map[string]bool{"sudo": true, "su": true, "doas": true, "pkexec": true, "passwd": true, "ssh": true, "gpg": true}

func checkPathOrder(e *env, pathEnv string, c *findings.Collector) {
	if pathEnv == "" {
		return
	}
	for _, d := range strings.Split(pathEnv, ":") {
		d = path.Clean(strings.TrimSpace(d))
		if d == "." || d == "" {
			c.Add(findings.Finding{Rule: "host.path-user-writable", Severity: findings.SevFail, Path: "PATH", CWE: cwe("CWE-427"),
				Message: "PATH contains the current directory (empty or \".\" entry): any repository you cd into can shadow system commands",
				Fix:     "remove the empty / \".\" entry from PATH"})
			continue
		}
		if systemPathDirs[d] {
			break // only entries ahead of the first system dir matter
		}
		st, err := e.stat(d)
		if err != nil || !st.IsDir() {
			continue
		}
		owner, _ := fileUID(st)
		mode := st.Mode().Perm()
		if owner == 0 && mode&0o022 == 0 {
			continue
		}
		why := fmt.Sprintf("owned by uid %d", owner)
		if mode&0o002 != 0 {
			why = "world-writable"
		} else if mode&0o020 != 0 && owner == 0 {
			why = "group-writable"
		}
		var shadows, priv []string
		for _, sys := range []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin"} {
			for _, f := range e.glob(path.Join(sys, "*")) {
				n := path.Base(f)
				if e.exists(path.Join(d, n)) && !containsStr(shadows, n) {
					shadows = append(shadows, n)
					if privilegedCmds[n] {
						priv = append(priv, n)
					}
				}
			}
		}
		c.Add(findings.Finding{Rule: "host.path-user-writable", Severity: findings.SevWarn, Path: d, CWE: cwe("CWE-427"),
			Message: fmt.Sprintf("user-writable PATH entry (%s) comes before the system directories; anything that can write there (a repo's setup script, a fake interview task) can shadow system commands", why),
			Fix:     "put user directories after /usr/bin:/bin, or keep them root-owned; run foreign repositories and test tasks only through oss-run"})
		if len(priv) > 0 {
			c.Add(findings.Finding{Rule: "host.path-shadow", Severity: findings.SevFail, Path: d, CWE: cwe("CWE-427"),
				Message: "user-writable PATH entry shadows privileged commands: " + strings.Join(priv, ", "),
				Fix:     "inspect and remove these binaries; reinstall from the distribution and rotate credentials typed into them"})
		} else if len(shadows) > 0 {
			if len(shadows) > 12 {
				shadows = append(shadows[:12], fmt.Sprintf("… (%d more)", len(shadows)-12))
			}
			c.Add(findings.Finding{Rule: "host.path-shadow", Severity: findings.SevInfo, Path: d,
				Message: "shadows system commands: " + strings.Join(shadows, ", ") + " (expected for pyenv shims, Homebrew, ~/.local/bin; verify they are yours)"})
		}
	}
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// ---- version managers / Homebrew ----

// tamperSignalRe matches code that has no business in a version-manager
// dispatcher or shim (network fetch, decode-and-run, reverse shells).
var tamperSignalRe = regexp.MustCompile(`(?i)(\bcurl\b|\bwget\b|/dev/tcp/|\bnc\s+-|\bncat\b|base64\s+(-d|--decode)|\bpython3?\s+-c\b|\bperl\s+-e\b|osascript|cloudflared|\bnohup\b|launchctl|crontab|authorized_keys)`)

var brewPrefixes = []string{"/home/linuxbrew/.linuxbrew", "/opt/homebrew", "/usr/local"}

var versionManagers = []string{"pyenv", "rbenv", "nodenv"}

func checkVersionManagers(e *env, c *findings.Collector) {
	refs := []string{"https://www.theregister.com/security/2026/11/03/north-korean-fake-job-interview-led-to-63b-binance-heist/5307398",
		"https://www.reversinglabs.com/blog/binance-heist-what-we-know-and-what-rl-sees-in-tradertraitors-toolkit"}
	tamper := func(at, msg string) {
		c.Add(findings.Finding{Rule: "host.version-manager-tamper", Severity: findings.SevFail, Path: at, CWE: cwe("CWE-506", "CWE-427"), Message: msg,
			Fix:  "reinstall the tool from its first-party source (brew reinstall / fresh git clone), compare with a known-good copy, and treat the machine as compromised: rotate every credential it held",
			Refs: refs})
	}
	scan := func(f, what string) {
		st, err := os.Lstat(e.path(f))
		if err != nil || !st.Mode().IsRegular() {
			return
		}
		b, err := e.read(f)
		if err != nil {
			return
		}
		if m := tamperSignalRe.Find(b); m != nil {
			tamper(f, fmt.Sprintf("%s contains %q, which a version-manager dispatcher/shim never does (the Nov 2026 exchange heist replaced Homebrew's pyenv this way)", what, string(m)))
		}
	}
	var roots []string
	for _, h := range homeDirs(e) {
		for _, vm := range versionManagers {
			root := path.Join(h, "."+vm)
			roots = append(roots, root)
			scan(path.Join(root, "libexec", vm), vm+" dispatcher")
			for _, s := range e.glob(path.Join(root, "shims", "*")) {
				scan(s, vm+" shim")
			}
		}
		brewPrefixesHome := path.Join(h, ".linuxbrew")
		roots = append(roots, brewPrefixesHome)
	}
	prefixes := append(append([]string{}, brewPrefixes...), roots...)
	for _, pre := range prefixes {
		for _, vm := range versionManagers {
			for _, cellar := range e.glob(path.Join(pre, "Cellar", vm, "*")) {
				main := path.Join(cellar, "libexec", vm)
				scan(main, "Homebrew "+vm+" dispatcher")
				// Homebrew writes INSTALL_RECEIPT.json at install time;
				// the dispatcher being rewritten later is a tamper sign.
				if rs, err := e.stat(path.Join(cellar, "INSTALL_RECEIPT.json")); err == nil {
					if ms, err := os.Lstat(e.path(main)); err == nil && ms.ModTime().Sub(rs.ModTime()) > 3600e9 {
						c.Add(findings.Finding{Rule: "host.version-manager-tamper", Severity: findings.SevWarn, Path: main, CWE: cwe("CWE-506"),
							Message: fmt.Sprintf("%s was modified %s after Homebrew installed it", vm, ms.ModTime().Sub(rs.ModTime()).Round(3600e9)),
							Fix:     "brew reinstall " + vm + " and compare; find out what rewrote it", Refs: refs})
					}
				}
			}
			// bin/<vm> must point into Cellar/<vm>/.
			link := path.Join(pre, "bin", vm)
			if t, err := os.Readlink(e.path(link)); err == nil {
				if !strings.Contains(t, "Cellar/"+vm+"/") {
					tamper(link, fmt.Sprintf("Homebrew %s link points to %q, outside Cellar/%s/", vm, t, vm))
				}
			}
		}
		link := path.Join(pre, "bin", "brew")
		if t, err := os.Readlink(e.path(link)); err == nil && !strings.HasSuffix(t, "Homebrew/bin/brew") {
			tamper(link, fmt.Sprintf("brew link points to %q instead of Homebrew/bin/brew", t))
		}
	}
}

// ---- IDE extension auto-update ----

var ideSettingsDirs = []string{"Code", "Code - Insiders", "Cursor", "Windsurf", "VSCodium"}

var autoUpdateOffRe = regexp.MustCompile(`"extensions\.autoUpdate"\s*:\s*(false|"off"|"onlySelectedExtensions")`)

func checkExtensionAutoUpdate(e *env, c *findings.Collector) {
	for _, h := range homeDirs(e) {
		for _, d := range ideSettingsDirs {
			dir := path.Join(h, ".config", d, "User")
			if st, err := e.stat(dir); err != nil || !st.IsDir() {
				continue
			}
			f := path.Join(dir, "settings.json")
			b, _ := e.read(f)
			if autoUpdateOffRe.Match(b) {
				continue
			}
			c.Add(findings.Finding{Rule: "host.ide-extension-autoupdate", Severity: findings.SevWarn, Path: f, CWE: cwe("CWE-494"),
				Message: d + ": extensions auto-update to whatever the marketplace serves (the trojanized Claude Code 2.1.312/2.1.313 arrived this way); pin reviewed versions",
				Fix:     `set "extensions.autoUpdate": false (or "onlySelectedExtensions") and update extensions deliberately after review`,
				Refs:    []string{"https://cursor.com/blog/claude-code-extension-security-notice"}})
		}
	}
}
