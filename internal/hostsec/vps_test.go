package hostsec

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

// Synthetic Ubuntu 24.04 VPS image as delivered by a provider template:
// keys from the template host, password + root login via cloud-init,
// no firewall, no fail2ban, stale kernel, no auto-updates, git 2.43.

const sshTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0
`

const sshTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2001 1 0000000000000000 100 0 0 10 0
`

func templateVps(t *testing.T) *tree {
	tr := newTree(t)
	tr.write("/etc/os-release", "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nVERSION_CODENAME=noble\n")
	tr.write("/etc/hostname", "vps-hel-01\n")
	tr.write("/var/lib/cloud/data/instance-id", "i-0abc\n")
	tr.age("/var/lib/cloud/data/instance-id", 24*time.Hour)
	for _, k := range []struct{ name, typ string }{{"rsa", "ssh-rsa"}, {"ecdsa", "ecdsa-sha2-nistp256"}, {"dsa", "ssh-dss"}} {
		p := "/etc/ssh/ssh_host_" + k.name + "_key.pub"
		tr.write(p, k.typ+" AAAAsynthetic root@fi-fi1-srv-kvm-272\n")
		tr.age(p, 200*24*time.Hour)
	}
	tr.write("/etc/ssh/sshd_config", "# Ubuntu default\nInclude /etc/ssh/sshd_config.d/*.conf\n\nPasswordAuthentication no\nPermitRootLogin yes\nKbdInteractiveAuthentication no\n")
	tr.write("/etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n")
	tr.write("/proc/sys/kernel/osrelease", "6.8.0-31-generic\n")
	tr.write("/proc/version", "Linux version 6.8.0-31-generic (buildd@x) #31-Ubuntu SMP\n")
	tr.write("/var/lib/dpkg/status", pkg("linux-image-6.8.0-31-generic", "6.8.0-31.31", "amd64")+pkg("linux-image-6.8.0-88-generic", "6.8.0-88.89", "amd64")+
		pkg("git", "1:2.43.0-1ubuntu7.3", "amd64")+pkg("openssh-server", "1:9.6p1-3ubuntu13.5", "amd64"))
	tr.write("/var/run/reboot-required", "*** System restart required ***\n")
	tr.write("/var/run/reboot-required.pkgs", "linux-image-6.8.0-88-generic\n")
	tr.write("/etc/apt/apt.conf.d/10periodic", "APT::Periodic::Update-Package-Lists \"0\";\n")
	tr.write("/proc/net/tcp", sshTCP)
	tr.write("/proc/net/tcp6", sshTCP6)
	return tr
}

func runVps(t *testing.T, tr *tree, opt Options) *Report {
	t.Helper()
	opt.Root, opt.Vps, opt.Now = tr.root, true, func() time.Time { return now }
	opt.Groups = func() ([]string, error) { return nil, nil }
	rep, err := Run(nil, opt)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func sevs(fs []findings.Finding) string {
	var s []string
	for _, f := range fs {
		s = append(s, f.Severity+":"+f.Path)
	}
	return strings.Join(s, " ")
}

func hasCWE(f findings.Finding, id string) bool {
	for _, c := range f.CWE {
		if c == id {
			return true
		}
	}
	return false
}

func TestVpsTemplateImage(t *testing.T) {
	rep := runVps(t, templateVps(t), Options{})
	if rep.OK {
		t.Fatal("template VPS must fail")
	}
	if rep.Apt != nil || rep.Net != nil || rep.Vps == nil {
		t.Fatalf("vps alone must not run apt/net: %+v", rep)
	}

	keys := find(rep, "host.ssh-hostkeys-template")
	var dsaFail, tmplWarn, noEd bool
	for _, f := range keys {
		switch {
		case f.Severity == findings.SevFail && strings.Contains(f.Path, "_dsa_"):
			dsaFail = hasCWE(f, "CWE-327")
		case f.Severity == findings.SevWarn && strings.Contains(f.Message, "root@fi-fi1-srv-kvm-272") && strings.Contains(f.Message, "older"):
			tmplWarn = hasCWE(f, "CWE-1394") && strings.Contains(f.Fix, "ssh-keygen -A")
		case f.Severity == findings.SevWarn && f.Message == "no ed25519 host key":
			noEd = true
		}
	}
	if !dsaFail || !tmplWarn || !noEd {
		t.Fatalf("host keys: dsa=%v template=%v noEd25519=%v\n%+v", dsaFail, tmplWarn, noEd, keys)
	}

	pw := one(t, rep, "host.sshd-effective", findings.SevFail, "PasswordAuthentication yes")
	if !strings.Contains(pw.Message, "50-cloud-init.conf:1") || !strings.Contains(pw.Message, "/etc/ssh/sshd_config:4 (no)") || !hasCWE(pw, "CWE-309") {
		t.Errorf("first-match-wins evidence: %s", pw.Message)
	}
	one(t, rep, "host.sshd-effective", findings.SevFail, "PermitRootLogin yes")

	ks := one(t, rep, "host.kernel-stale", findings.SevWarn, "6.8.0-88-generic")
	if !strings.Contains(ks.Message, "reboot-required") {
		t.Errorf("kernel-stale: %s", ks.Message)
	}
	na := one(t, rep, "host.no-auto-updates", findings.SevWarn, "not installed")
	if !strings.Contains(na.Message, "20auto-upgrades is missing") {
		t.Errorf("auto-updates: %s", na.Message)
	}
	one(t, rep, "host.firewall-off", findings.SevFail, "default-deny")
	ex := one(t, rep, "host.ssh-exposed", findings.SevWarn, "0.0.0.0:22/tcp")
	if !strings.Contains(ex.Message, "[::]:22/tcp") {
		t.Errorf("ssh-exposed v6: %s", ex.Message)
	}
	one(t, rep, "host.no-bruteforce-protection", findings.SevWarn, "reachable")
	one(t, rep, "host.ntp-unsynced", findings.SevWarn, "no NTP client")
	g := one(t, rep, "host.git-cve-2026-111760", findings.SevWarn, "git 2.43.0")
	if len(g.Refs) == 0 || !strings.Contains(g.Refs[0], "GHSA-vp2w-7xxj-jvxr") {
		t.Errorf("git refs: %+v", g.Refs)
	}
	if rep.Vps.Hostname != "vps-hel-01" || rep.Vps.FirstBootBy != "/var/lib/cloud/data/instance-id" || rep.Vps.Sshd["passwordauthentication"] != "yes" {
		t.Errorf("state: %+v", rep.Vps)
	}
}

func TestSshdFirstMatchWins(t *testing.T) {
	tr := newTree(t)
	// The hardening drop-in sorts before 50-cloud-init, so its "no" wins
	// even though cloud-init and the main file both say yes later.
	tr.write("/etc/ssh/sshd_config", "Include sshd_config.d/*.conf\nPasswordAuthentication yes\nPermitRootLogin yes\nMatch User backup\n  PasswordAuthentication yes\n  PermitRootLogin yes\n")
	tr.write("/etc/ssh/sshd_config.d/00-hardening.conf", "PasswordAuthentication no\nPermitRootLogin prohibit-password\n")
	tr.write("/etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n")
	e := &env{root: tr.root}
	s := parseSshdConfig(e, "/etc/ssh/sshd_config")
	if v, at := s.get("passwordauthentication"); v != "no" || at != "/etc/ssh/sshd_config.d/00-hardening.conf:1" {
		t.Fatalf("passwordauthentication = %q at %s", v, at)
	}
	if len(s.Shadowed["passwordauthentication"]) != 2 {
		t.Errorf("shadowed (Match block must not count): %+v", s.Shadowed["passwordauthentication"])
	}
	rep := runVps(t, tr, Options{})
	if f := find(rep, "host.sshd-effective"); len(f) == 0 || f[0].Severity != findings.SevInfo {
		t.Fatalf("hardened config: %s", sevs(f))
	}

	// Keyword=value, case-insensitive keywords, Match inside an included
	// file ends with that file.
	tr2 := newTree(t)
	tr2.write("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\npermitrootlogin=no\n")
	tr2.write("/etc/ssh/sshd_config.d/10-match.conf", "Match Address 10.0.0.0/8\n  PasswordAuthentication yes\n")
	tr2.write("/etc/ssh/sshd_config.d/20-pw.conf", "PASSWORDAUTHENTICATION no\n")
	s2 := parseSshdConfig(&env{root: tr2.root}, "/etc/ssh/sshd_config")
	if v, _ := s2.get("passwordauthentication"); v != "no" {
		t.Errorf("match in include leaked: %q", v)
	}
	if v, _ := s2.get("permitrootlogin"); v != "no" {
		t.Errorf("key=value: %q", v)
	}

	// No PasswordAuthentication anywhere: the OpenSSH default is yes.
	tr3 := newTree(t)
	tr3.write("/etc/ssh/sshd_config", "Port 2222\n")
	rep3 := runVps(t, tr3, Options{})
	one(t, rep3, "host.sshd-effective", findings.SevFail, "OpenSSH default")
}

func TestSshdTOverridesFiles(t *testing.T) {
	tr := templateVps(t)
	rep := runVps(t, tr, Options{SshdT: []byte("port 2222\npasswordauthentication no\npermitrootlogin without-password\npubkeyauthentication yes\n")})
	for _, f := range find(rep, "host.sshd-effective") {
		if f.Severity != findings.SevInfo {
			t.Errorf("sshd -T says no: %+v", f)
		}
	}
	if rep.Vps.SshdSource != "sshd -T" || len(rep.Vps.SSHPorts) != 1 || rep.Vps.SSHPorts[0] != 2222 {
		t.Errorf("state: %+v", rep.Vps)
	}
	// Port 22 is not sshd's port any more, so nothing is "ssh exposed".
	if f := find(rep, "host.ssh-exposed"); len(f) != 0 {
		t.Errorf("ssh-exposed on wrong port: %+v", f)
	}
}

func TestVpsHardened(t *testing.T) {
	tr := templateVps(t)
	os.Remove(filepath.Join(tr.root, "etc/ssh/ssh_host_dsa_key.pub"))
	for _, k := range []string{"rsa", "ecdsa", "ed25519"} {
		tr.write("/etc/ssh/ssh_host_"+k+"_key.pub", "ssh-"+k+" AAAAsynthetic root@vps-hel-01\n")
	}
	tr.write("/etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication no\n")
	tr.write("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin prohibit-password\n")
	os.Remove(filepath.Join(tr.root, "var/run/reboot-required"))
	tr.write("/proc/sys/kernel/osrelease", "6.8.0-88-generic\n")
	tr.write("/var/lib/dpkg/status", pkg("linux-image-6.8.0-88-generic", "6.8.0-88.89", "amd64")+pkg("unattended-upgrades", "2.9.1+nmu4ubuntu1", "all")+
		pkg("systemd-timesyncd", "255.4-1ubuntu8", "amd64")+pkg("git", "1:2.43.0-1ubuntu7.3", "amd64"))
	tr.write("/etc/apt/apt.conf.d/10periodic", "")
	tr.write("/etc/apt/apt.conf.d/20auto-upgrades", "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n")
	tr.write("/run/systemd/timesync/synchronized", "")
	// Distro backport: the Debian changelog names the CVE.
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte("git (1:2.43.0-1ubuntu7.3) noble-security; urgency=medium\n  * SECURITY UPDATE: CVE-2026-111760\n"))
	zw.Close()
	tr.write("/usr/share/doc/git/changelog.Debian.gz", gz.String())
	ufw := "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     LIMIT IN    203.0.113.0/24\n"
	rep := runVps(t, tr, Options{UfwStatus: []byte(ufw), Timedatectl: nil})
	for _, f := range rep.Findings {
		if f.Severity != findings.SevInfo {
			t.Errorf("hardened VPS: unexpected %s %s %s", f.Severity, f.Rule, f.Message)
		}
	}
	if !rep.OK {
		t.Error("hardened VPS must pass")
	}
	one(t, rep, "host.ssh-exposed", findings.SevInfo, "specific sources")
	one(t, rep, "host.git-cve-2026-111760", findings.SevInfo, "backport")
	if rep.Vps.Firewall == "" || len(rep.Vps.BruteForce) == 0 || rep.Vps.NTP != "systemd-timesyncd synchronized" {
		t.Errorf("state: %+v", rep.Vps)
	}
}

func TestVpsFirewallAlternatives(t *testing.T) {
	nft := "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\tct state established,related accept\n\t}\n}\n"
	rep := runVps(t, templateVps(t), Options{Nft: []byte(nft)})
	if f := find(rep, "host.firewall-off"); len(f) != 0 {
		t.Errorf("nft input drop: %+v", f)
	}
	tr := templateVps(t)
	tr.write("/etc/iptables/rules.v4", "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n")
	if f := find(runVps(t, tr, Options{}), "host.firewall-off"); len(f) != 0 {
		t.Errorf("iptables-persistent: %+v", f)
	}
	tr2 := templateVps(t)
	tr2.write("/etc/nftables.conf", "table inet filter { chain input { type filter hook input priority 0; policy accept; } }\n")
	if f := find(runVps(t, tr2, Options{}), "host.firewall-off"); len(f) != 1 || !strings.Contains(f[0].Message, "nftables.conf") {
		t.Errorf("nftables accept policy: %+v", f)
	}
}

func TestVpsNTPFromTimedatectl(t *testing.T) {
	rep := runVps(t, templateVps(t), Options{Timedatectl: []byte("Timezone=Europe/Helsinki\nNTP=yes\nNTPSynchronized=no\n")})
	f := one(t, rep, "host.ntp-unsynced", findings.SevWarn, "NTPSynchronized=no")
	if !hasCWE(f, "CWE-778") {
		t.Errorf("cwe: %+v", f.CWE)
	}
	rep = runVps(t, templateVps(t), Options{Timedatectl: []byte("NTP=yes\nNTPSynchronized=yes\n")})
	if f := find(rep, "host.ntp-unsynced"); len(f) != 0 {
		t.Errorf("synced: %+v", f)
	}
}

func TestGitVulnerable111760(t *testing.T) {
	cases := map[string]bool{
		"git version 2.34.1": true, "git version 2.49.0": true, "git version 2.50.1": true, "git version 2.50.2": false,
		"git version 2.51.2": true, "git version 2.51.3": false, "git version 2.55.0": true, "git version 2.55.1": false,
		"git version 2.56.0": true, "git version 2.56.1": false, "git version 2.57.0": false, "git version 3.0.0": false,
		"1:2.43.0-1ubuntu7.3": true, "git version 2.56.1.windows.1": false,
	}
	for in, want := range cases {
		maj, min, patch, ok := upstreamGit(in)
		if !ok || GitVulnerable111760(maj, min, patch) != want {
			t.Errorf("%s: ok=%v vulnerable=%v want %v", in, ok, GitVulnerable111760(maj, min, patch), want)
		}
	}
	rep := runVps(t, templateVps(t), Options{GitVersion: []byte("git version 2.56.1\n")})
	if f := find(rep, "host.git-cve-2026-111760"); len(f) != 0 {
		t.Errorf("patched git: %+v", f)
	}
	rep = runVps(t, templateVps(t), Options{GitVersion: []byte("git version 2.34.1\n")})
	one(t, rep, "host.git-cve-2026-111760", findings.SevWarn, "git 2.34.1 (git --version)")
}
