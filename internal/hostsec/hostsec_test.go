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

var now = time.Date(2026, 11, 2, 20, 0, 0, 0, time.UTC)

type tree struct {
	t    *testing.T
	root string
}

func newTree(t *testing.T) *tree { return &tree{t: t, root: t.TempDir()} }

func (tr *tree) write(p, data string) string {
	tr.t.Helper()
	full := filepath.Join(tr.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		tr.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
		tr.t.Fatal(err)
	}
	return full
}

func (tr *tree) age(p string, d time.Duration) {
	tr.t.Helper()
	at := now.Add(-d)
	if err := os.Chtimes(filepath.Join(tr.root, p), at, at); err != nil {
		tr.t.Fatal(err)
	}
}

func (tr *tree) symlink(p, target string) {
	tr.t.Helper()
	full := filepath.Join(tr.root, p)
	_ = os.MkdirAll(filepath.Dir(full), 0o755)
	if err := os.Symlink(target, full); err != nil {
		tr.t.Fatal(err)
	}
}

func pkg(name, ver, arch string) string {
	return "Package: " + name + "\nStatus: install ok installed\nArchitecture: " + arch + "\nVersion: " + ver + "\nDescription: x\n continued line\n\n"
}

const secLists = "/var/lib/apt/lists/security.ubuntu.com_ubuntu_dists_jammy-security_"

// healthyJammy builds an up-to-date Ubuntu 22.04 tree.
func healthyJammy(t *testing.T) *tree {
	tr := newTree(t)
	tr.write("/etc/os-release", "PRETTY_NAME=\"Ubuntu 22.04.5 LTS\"\nVERSION_CODENAME=jammy\nID=ubuntu\n")
	tr.write("/var/lib/dpkg/status",
		pkg("libc6", "2.35-0ubuntu3.10", "amd64")+
			pkg("openssl", "3.0.2-0ubuntu1.20", "amd64")+
			pkg("tzdata", "2025b-0ubuntu0.22.04", "all")+
			pkg("unattended-upgrades", "2.8ubuntu1", "all")+
			pkg("linux-image-5.15.0-202-generic", "5.15.0-202.212", "amd64"))
	tr.write(secLists+"InRelease", "Origin: Ubuntu\nSuite: jammy-security\nDate: "+now.Add(-6*time.Hour).Format(time.RFC1123)+"\n")
	tr.write(secLists+"main_binary-amd64_Packages",
		"Package: libc6\nArchitecture: amd64\nVersion: 2.35-0ubuntu3.10\n\nPackage: openssl\nArchitecture: amd64\nVersion: 3.0.2-0ubuntu1.19\n\nPackage: tzdata\nArchitecture: all\nVersion: 2025b-0ubuntu0.22.04\n\nPackage: notinstalled\nArchitecture: amd64\nVersion: 9\n\n")
	tr.write("/etc/apt/apt.conf.d/20auto-upgrades", "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n")
	tr.write("/etc/apt/apt.conf.d/50unattended-upgrades", "Unattended-Upgrade::Allowed-Origins {\n\t\"${distro_id}:${distro_codename}-security\";\n//\t\"${distro_id}:${distro_codename}-updates\";\n};\n")
	tr.write("/etc/systemd/system/timers.target.wants/apt-daily-upgrade.timer", "[Timer]\n")
	tr.write("/var/lib/apt/periodic/unattended-upgrades-stamp", "")
	tr.age("/var/lib/apt/periodic/unattended-upgrades-stamp", 10*time.Hour)
	tr.write("/proc/sys/kernel/osrelease", "5.15.0-202-generic\n")
	tr.write("/proc/version", "Linux version 5.15.0-202-generic (buildd@lcy02-amd64-001) (gcc 11.4.0) #212-Ubuntu SMP Fri Oct 10 12:00:00 UTC 2026\n")
	return tr
}

func run(t *testing.T, tr *tree, p *Policy, opt Options) *Report {
	t.Helper()
	opt.Root = tr.root
	opt.Now = func() time.Time { return now }
	if opt.Groups == nil {
		opt.Groups = func() ([]string, error) { return []string{"admin", "docker"}, nil }
	}
	rep, err := Run(p, opt)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func find(rep *Report, rule string) []findings.Finding {
	var out []findings.Finding
	for _, f := range rep.Findings {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	return out
}

func one(t *testing.T, rep *Report, rule, sev, contains string) findings.Finding {
	t.Helper()
	for _, f := range find(rep, rule) {
		if f.Severity == sev && strings.Contains(f.Message, contains) {
			return f
		}
	}
	t.Fatalf("no %s %s finding containing %q; got:\n%s", sev, rule, contains, dump(rep))
	return findings.Finding{}
}

func none(t *testing.T, rep *Report, rule string) {
	t.Helper()
	if fs := find(rep, rule); len(fs) > 0 {
		t.Fatalf("unexpected %s findings:\n%s", rule, dump(rep))
	}
}

func dump(rep *Report) string {
	var b strings.Builder
	for _, f := range rep.Findings {
		b.WriteString("  " + f.Severity + " " + f.Rule + " " + f.Path + ": " + f.Message + "\n")
	}
	return b.String()
}

var fragnesia = KernelFloor{Name: "Fragnesia", CVE: "CVE-2026-46300", Min: "5.15.0-181.191"}

func TestAptHealthy(t *testing.T) {
	tr := healthyJammy(t)
	rep := run(t, tr, &Policy{KernelFloors: []KernelFloor{fragnesia}}, Options{Apt: true})
	if !rep.OK {
		t.Fatalf("healthy host failed:\n%s", dump(rep))
	}
	if rep.OS != "Ubuntu 22.04.5 LTS" || rep.Codename != "jammy" {
		t.Errorf("os = %q %q", rep.OS, rep.Codename)
	}
	if rep.Apt.Installed != 5 || len(rep.Apt.SecurityPending) != 0 {
		t.Errorf("apt state = %+v", rep.Apt)
	}
	one(t, rep, "apt.lists-age", findings.SevInfo, "jammy-security index is 6h old")
	one(t, rep, "apt.security-pending", findings.SevInfo, "no pending")
	one(t, rep, "apt.unattended", findings.SevInfo, "enabled for the security pocket")
	one(t, rep, "kernel.floor", findings.SevInfo, "5.15.0-202.212 ≥ Fragnesia (CVE-2026-46300) floor 5.15.0-181.191")
	none(t, rep, "apt.reboot-required")
	none(t, rep, "snap.present")
	if rep.Kernel.Package != "5.15.0-202.212" || rep.Kernel.Series != "5.15" {
		t.Errorf("kernel = %+v", rep.Kernel)
	}
	if rep.Net != nil {
		t.Error("net checks ran although only apt was selected")
	}
}

func TestAptPendingAndStale(t *testing.T) {
	tr := healthyJammy(t)
	tr.write(secLists+"InRelease", "Suite: jammy-security\nDate: "+now.Add(-80*time.Hour).Format(time.RFC1123)+"\n")
	// gzip index with newer libc6 and openssl.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte("Package: libc6\nArchitecture: amd64\nVersion: 2.35-0ubuntu3.11\n\nPackage: libc6\nArchitecture: amd64\nVersion: 2.35-0ubuntu3.12\n\nPackage: openssl\nArchitecture: i386\nVersion: 3.0.2-0ubuntu1.99\n\nPackage: tzdata\nArchitecture: all\nVersion: 2026a-0ubuntu0.22.04\n\n"))
	gz.Close()
	tr.write(secLists+"universe_binary-amd64_Packages.gz", buf.String())
	// Not a security suite: ignored.
	tr.write("/var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_jammy-updates_main_binary-amd64_Packages", "Package: openssl\nArchitecture: amd64\nVersion: 9.9\n\n")
	rep := run(t, tr, nil, Options{Apt: true})
	one(t, rep, "apt.lists-stale", findings.SevWarn, "3d old")
	f := one(t, rep, "apt.security-pending", findings.SevWarn, "2 installed package(s)")
	if !strings.Contains(f.Message, "libc6 2.35-0ubuntu3.10 → 2.35-0ubuntu3.12") || !strings.Contains(f.Message, "tzdata") || strings.Contains(f.Message, "openssl") {
		t.Errorf("pending message = %q", f.Message)
	}
	if !rep.OK {
		t.Errorf("warnings only: OK should stay true without strict:\n%s", dump(rep))
	}
}

func TestAptThresholdsFail(t *testing.T) {
	tr := healthyJammy(t)
	tr.write(secLists+"InRelease", "Suite: jammy-security\n")
	tr.age(secLists+"InRelease", 9*24*time.Hour) // no Date: mtime fallback
	tr.write(secLists+"main_binary-amd64_Packages", "Package: libc6\nArchitecture: amd64\nVersion: 2.35-0ubuntu3.11\n\n")
	tr.write("/var/run/reboot-required", "*** System restart required ***\n")
	tr.write("/var/run/reboot-required.pkgs", "linux-image-5.15.0-203-generic\nlibc6\nlibc6\n")
	tr.age("/var/run/reboot-required", 8*24*time.Hour)
	failAt := 1
	rep := run(t, tr, &Policy{Apt: &AptPolicy{SecurityFail: failAt}}, Options{Apt: true})
	if rep.OK {
		t.Fatalf("expected failure:\n%s", dump(rep))
	}
	for _, want := range []struct{ rule, msg string }{
		{"apt.lists-stale", "9d old"},
		{"apt.security-pending", "1 installed"},
		{"apt.reboot-required", "by linux-image-5.15.0-203-generic, libc6"},
	} {
		found := false
		for _, f := range find(rep, want.rule) {
			if f.Severity == findings.SevFail && strings.Contains(f.Message, want.msg) {
				found = true
			}
		}
		if !found {
			t.Errorf("no fail %s containing %q:\n%s", want.rule, want.msg, dump(rep))
		}
	}
	if !rep.Apt.RebootRequired || len(rep.Apt.RebootPackages) != 2 {
		t.Errorf("reboot state = %+v", rep.Apt)
	}
}

func TestAptNoSecuritySource(t *testing.T) {
	tr := healthyJammy(t)
	os.Remove(filepath.Join(tr.root, secLists+"InRelease"))
	rep := run(t, tr, nil, Options{Apt: true})
	one(t, rep, "apt.no-security-source", findings.SevFail, "jammy-security")
	if rep.OK {
		t.Error("missing security source must fail")
	}

	tr = healthyJammy(t)
	os.Remove(filepath.Join(tr.root, secLists+"InRelease"))
	tr.write("/var/lib/apt/lists/security.ubuntu.com_ubuntu_dists_focal-security_InRelease", "Date: "+now.Format(time.RFC1123)+"\n")
	rep = run(t, tr, nil, Options{Apt: true})
	one(t, rep, "apt.no-security-source", findings.SevWarn, "not for the installed release (jammy-security)")
}

func TestAptUnattendedBroken(t *testing.T) {
	tr := healthyJammy(t)
	tr.write("/etc/apt/apt.conf.d/20auto-upgrades", "APT::Periodic::Update-Package-Lists \"1\";\n// APT::Periodic::Unattended-Upgrade \"1\";\nAPT::Periodic::Unattended-Upgrade \"0\";\n")
	tr.write("/etc/apt/apt.conf.d/50unattended-upgrades", "Unattended-Upgrade::Allowed-Origins {\n//\t\"${distro_id}:${distro_codename}-security\";\n\t\"${distro_id}ESMApps:${distro_codename}-apps\";\n};\n")
	os.Remove(filepath.Join(tr.root, "/etc/systemd/system/timers.target.wants/apt-daily-upgrade.timer"))
	tr.symlink("/etc/systemd/system/apt-daily-upgrade.timer", "/dev/null")
	rep := run(t, tr, nil, Options{Apt: true})
	f := one(t, rep, "apt.unattended", findings.SevWarn, "not healthy")
	for _, p := range []string{"not enabled", "no security pocket", "timer is masked"} {
		if !strings.Contains(f.Message, p) {
			t.Errorf("message %q lacks %q", f.Message, p)
		}
	}
	no := false
	rep = run(t, tr, &Policy{Apt: &AptPolicy{RequireUnattended: &no}}, Options{Apt: true})
	one(t, rep, "apt.unattended", findings.SevInfo, "not healthy")
}

func TestAptUnattendedStaleStamp(t *testing.T) {
	tr := healthyJammy(t)
	tr.age("/var/lib/apt/periodic/unattended-upgrades-stamp", 5*24*time.Hour)
	rep := run(t, tr, nil, Options{Apt: true})
	one(t, rep, "apt.unattended", findings.SevWarn, "last ran 5d ago")

	os.Remove(filepath.Join(tr.root, "/var/lib/apt/periodic/unattended-upgrades-stamp"))
	rep = run(t, tr, nil, Options{Apt: true})
	one(t, rep, "apt.unattended", findings.SevWarn, "never run")
}

func TestAptInterruptedAndESM(t *testing.T) {
	tr := healthyJammy(t)
	tr.write("/var/lib/dpkg/updates/0001", "x")
	st, _ := os.ReadFile(filepath.Join(tr.root, "/var/lib/dpkg/status"))
	tr.write("/var/lib/dpkg/status", string(st)+"Package: half\nStatus: install ok half-configured\nArchitecture: amd64\nVersion: 1\n\n")
	tr.write("/var/lib/update-notifier/updates-available", "\n1 update can be applied immediately.\n\n73 additional security updates can be applied with ESM Apps.\nLearn more about enabling ESM Apps service at https://ubuntu.com/esm\n")
	rep := run(t, tr, nil, Options{Apt: true})
	if n := len(find(rep, "apt.dpkg-interrupted")); n != 2 {
		t.Errorf("dpkg-interrupted findings = %d:\n%s", n, dump(rep))
	}
	one(t, rep, "apt.esm-available", findings.SevInfo, "73 additional")
	if rep.Apt.ESMSecurity != 73 {
		t.Errorf("ESM = %d", rep.Apt.ESMSecurity)
	}
}

func TestAptUnavailable(t *testing.T) {
	tr := newTree(t)
	rep := run(t, tr, nil, Options{Apt: true})
	one(t, rep, "apt.unavailable", findings.SevInfo, "no dpkg database")
	one(t, rep, "kernel.unknown", findings.SevInfo, "cannot read")
	if !rep.OK {
		t.Error("a non-Debian host must not fail")
	}
}

func TestKernelFloors(t *testing.T) {
	tr := healthyJammy(t)
	floors := []KernelFloor{
		{Name: "future", CVE: "CVE-2027-0001", Min: "5.15.0-210.220", Refs: []string{"https://example.test"}},
		{Name: "baseline", Min: "5.15.0-205", Severity: "warn"},
		{Name: "noble", CVE: "CVE-2026-46300", Min: "6.8.0-124.124"},
		fragnesia,
	}
	rep := run(t, tr, &Policy{KernelFloors: floors}, Options{Apt: true})
	f := one(t, rep, "kernel.floor", findings.SevFail, "below the future (CVE-2027-0001) floor 5.15.0-210.220")
	if len(f.Refs) != 1 || !strings.Contains(f.Fix, "install a kernel") {
		t.Errorf("finding = %+v", f)
	}
	one(t, rep, "kernel.floor", findings.SevWarn, "below the baseline floor 5.15.0-205")
	one(t, rep, "kernel.floor", findings.SevInfo, "applies to the 6.8 series")
	one(t, rep, "kernel.floor", findings.SevInfo, "≥ Fragnesia")
	if rep.OK {
		t.Error("a failed floor must fail the run")
	}

	// A fixed kernel is installed but not booted.
	st, _ := os.ReadFile(filepath.Join(tr.root, "/var/lib/dpkg/status"))
	tr.write("/var/lib/dpkg/status", string(st)+pkg("linux-image-5.15.0-211-generic", "5.15.0-211.221", "amd64"))
	rep = run(t, tr, &Policy{KernelFloors: floors[:1]}, Options{Apt: true})
	f = one(t, rep, "kernel.floor", findings.SevFail, "below the future")
	if !strings.Contains(f.Fix, "already installed: reboot into it") {
		t.Errorf("fix = %q", f.Fix)
	}
	one(t, rep, "kernel.reboot-pending", findings.SevWarn, "5.15.0-211-generic (5.15.0-211.221) is installed")
}

func TestKernelDebian(t *testing.T) {
	tr := newTree(t)
	tr.write("/proc/sys/kernel/osrelease", "6.1.0-26-amd64\n")
	tr.write("/proc/version", "Linux version 6.1.0-26-amd64 (debian-kernel@lists.debian.org) (gcc-12) #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30)\n")
	rep := run(t, tr, &Policy{KernelFloors: []KernelFloor{{Name: "x", Min: "6.1.115-1"}}}, Options{Apt: true})
	if rep.Kernel.Package != "6.1.112-1" {
		t.Errorf("package = %q", rep.Kernel.Package)
	}
	one(t, rep, "kernel.floor", findings.SevFail, "6.1.112-1 is below the x floor 6.1.115-1")
}

func TestSnapsAndGroups(t *testing.T) {
	tr := healthyJammy(t)
	tr.write("/snap/lxd/current/meta/snap.yaml", "name: lxd\n")
	tr.write("/var/lib/snapd/snaps/multipass_1234.snap", "")
	rep := run(t, tr, &Policy{Apt: &AptPolicy{WarnSnaps: []string{"lxd", "multipass", "*"}}}, Options{Apt: true,
		Groups: func() ([]string, error) { return []string{"admin", "lxd"}, nil }})
	one(t, rep, "snap.present", findings.SevWarn, "snap lxd is installed: members of the lxd group")
	one(t, rep, "snap.present", findings.SevWarn, "snap multipass is installed")
	one(t, rep, "group.lxd", findings.SevWarn, "root-equivalent")
	if n := len(find(rep, "snap.present")); n != 2 {
		t.Errorf("snap findings = %d", n)
	}
}

func TestIgnoreAndStrict(t *testing.T) {
	tr := healthyJammy(t)
	tr.write("/snap/lxd/current/x", "")
	rep := run(t, tr, &Policy{Strict: true}, Options{Apt: true})
	if rep.OK || !rep.Strict {
		t.Fatalf("strict with a warning must fail:\n%s", dump(rep))
	}
	rep = run(t, tr, &Policy{Strict: true, Ignore: []string{"snap.present"}}, Options{Apt: true})
	if !rep.OK || rep.Ignored != 1 {
		t.Fatalf("ignored warning: ok=%v ignored=%d\n%s", rep.OK, rep.Ignored, dump(rep))
	}
}

func TestPolicyValidate(t *testing.T) {
	bad := []Policy{
		{KernelFloors: []KernelFloor{{Name: "x"}}},
		{KernelFloors: []KernelFloor{{Min: "5.15.0-1", CVE: "CVE-26-1"}}},
		{KernelFloors: []KernelFloor{{Min: "5.15.0-1", Severity: "info"}}},
		{Net: &NetPolicy{ExpectedPublic: []string{"http"}}},
		{Net: &NetPolicy{Sensitive: []string{"22/sctp"}}},
		{Net: &NetPolicy{ExpectedPublic: []string{"90-80"}}},
		{Apt: &AptPolicy{ListsWarnHours: -1}},
	}
	for i, p := range bad {
		if err := p.Validate(); err == nil {
			t.Errorf("case %d: expected a validation error for %+v", i, p)
		}
	}
	good := Policy{KernelFloors: []KernelFloor{fragnesia}, Net: &NetPolicy{ExpectedPublic: []string{"22", "137-138/udp", "8000:8010/tcp"}}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestParsePortSpec(t *testing.T) {
	for _, c := range []struct {
		spec  string
		proto string
		port  int
		want  bool
	}{
		{"22", "tcp", 22, true},
		{"22", "udp", 22, true},
		{"22/tcp", "udp", 22, false},
		{"137-138/udp", "udp", 138, true},
		{"137-138/udp", "udp", 139, false},
		{"8000:8010/tcp", "tcp", 8005, true},
	} {
		ps, err := ParsePortSpec(c.spec)
		if err != nil {
			t.Fatal(err)
		}
		if got := ps.Match(c.proto, c.port); got != c.want {
			t.Errorf("%s match %d/%s = %v", c.spec, c.port, c.proto, got)
		}
	}
}
