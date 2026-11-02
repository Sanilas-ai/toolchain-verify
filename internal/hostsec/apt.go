package hostsec

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

// AptState summarizes the apt/dpkg state.
type AptState struct {
	Installed       int        `json:"installed_packages"`
	SecurityLists   []List     `json:"security_lists,omitempty"`
	SecurityPending []Pending  `json:"security_pending,omitempty"`
	ESMSecurity     int        `json:"esm_security_available,omitempty"`
	Unattended      Unattended `json:"unattended_upgrades"`
	RebootRequired  bool       `json:"reboot_required"`
	RebootPackages  []string   `json:"reboot_packages,omitempty"`
}

// List is one security repository index.
type List struct {
	Suite    string    `json:"suite"`
	File     string    `json:"file"`
	Date     time.Time `json:"date,omitempty"`
	AgeHours int       `json:"age_hours"`
}

// Pending is an installed package with a newer version in a security pocket.
type Pending struct {
	Package   string `json:"package"`
	Installed string `json:"installed"`
	Available string `json:"available"`
	Suite     string `json:"suite"`
}

// Unattended describes unattended-upgrades.
type Unattended struct {
	Installed   bool   `json:"installed"`
	Enabled     bool   `json:"enabled"`
	Security    bool   `json:"security_origin"`
	TimerActive bool   `json:"timer_enabled"`
	LastRun     string `json:"last_run,omitempty"`
}

type dpkgPkg struct {
	Name, Version, Arch, Status string
}

// readDpkgStatus returns installed packages keyed by "name" and
// "name:arch".
func readDpkgStatus(e *env) map[string]dpkgPkg {
	out := map[string]dpkgPkg{}
	f, err := os.Open(e.path("/var/lib/dpkg/status"))
	if err != nil {
		return out
	}
	defer f.Close()
	_ = stanzas(f, []string{"Package", "Version", "Architecture", "Status"}, func(m map[string]string) {
		st := strings.Fields(m["Status"])
		if len(st) != 3 || (st[2] != "installed" && st[2] != "half-configured" && st[2] != "unpacked") {
			return
		}
		p := dpkgPkg{Name: m["Package"], Version: m["Version"], Arch: m["Architecture"], Status: st[2]}
		if p.Name == "" || p.Version == "" {
			return
		}
		out[p.Name+":"+p.Arch] = p
		if _, dup := out[p.Name]; !dup {
			out[p.Name] = p
		}
	})
	return out
}

const listsDir = "/var/lib/apt/lists"

// suiteOf extracts the suite from an apt list file name such as
// "archive.ubuntu.com_ubuntu_dists_jammy-security_main_binary-amd64_Packages".
func suiteOf(name string) string {
	_, rest, ok := strings.Cut(name, "_dists_")
	if !ok {
		return ""
	}
	suite, _, _ := strings.Cut(rest, "_")
	return suite
}

func isSecuritySuite(s string) bool {
	return strings.HasSuffix(s, "-security") || strings.HasSuffix(s, "/updates")
}

var dateRe = regexp.MustCompile(`(?m)^Date:\s*(.+)$`)

func checkApt(e *env, ap AptPolicy, rep *Report, dpkg map[string]dpkgPkg, c *findings.Collector) {
	st := &AptState{}
	rep.Apt = st
	names := map[string]bool{}
	for k, p := range dpkg {
		if !strings.Contains(k, ":") {
			names[p.Name] = true
		}
	}
	st.Installed = len(names)
	if len(dpkg) == 0 {
		c.Add(findings.Finding{Rule: "apt.unavailable", Severity: findings.SevInfo, Path: "/var/lib/dpkg/status",
			Message: "no dpkg database found; apt checks skipped (not a Debian/Ubuntu host?)"})
		return
	}

	// Security lists and their age.
	suites := map[string]bool{}
	for _, p := range e.glob(listsDir + "/*_InRelease") {
		base := filepath.Base(p)
		s := suiteOf(base)
		if !isSecuritySuite(s) {
			continue
		}
		suites[s] = true
		l := List{Suite: s, File: p}
		if data, err := e.read(p); err == nil {
			if m := dateRe.FindSubmatch(data); m != nil {
				if t, err := time.Parse(time.RFC1123, strings.TrimSpace(string(m[1]))); err == nil {
					l.Date = t
				} else if t, err := time.Parse("Mon, 2 Jan 2006 15:04:05 MST", strings.TrimSpace(string(m[1]))); err == nil {
					l.Date = t
				}
			}
		}
		if l.Date.IsZero() {
			if fi, err := e.stat(p); err == nil {
				l.Date = fi.ModTime()
			}
		}
		l.AgeHours = int(e.now.Sub(l.Date).Hours())
		st.SecurityLists = append(st.SecurityLists, l)
	}
	codename := rep.Codename
	want := codename + "-security"
	if len(st.SecurityLists) == 0 {
		c.Add(findings.Finding{Rule: "apt.no-security-source", Severity: findings.SevFail, Path: listsDir,
			Message: "no security repository index (" + orUnknown(want) + ") was downloaded: security updates are never offered",
			Fix:     "add the " + orUnknown(want) + " suite to /etc/apt/sources.list(.d) and run `sudo apt update`"})
	} else if codename != "" && !suites[want] {
		c.Add(findings.Finding{Rule: "apt.no-security-source", Severity: findings.SevWarn, Path: listsDir,
			Message: fmt.Sprintf("security indexes found for %s but not for the installed release (%s)", joinKeys(suites), want),
			Fix:     "point the security suite at " + want + " in sources.list and run `sudo apt update`"})
	}
	for _, l := range st.SecurityLists {
		age := time.Duration(l.AgeHours) * time.Hour
		sev := ""
		switch {
		case age > time.Duration(ap.ListsFailDays)*24*time.Hour:
			sev = findings.SevFail
		case age > time.Duration(ap.ListsWarnHours)*time.Hour:
			sev = findings.SevWarn
		}
		msg := fmt.Sprintf("%s index is %s old (Date %s)", l.Suite, humanAge(age), l.Date.UTC().Format("2006-01-02 15:04 MST"))
		if sev == "" {
			c.Add(findings.Finding{Rule: "apt.lists-age", Severity: findings.SevInfo, Path: l.File, Message: msg})
			continue
		}
		c.Add(findings.Finding{Rule: "apt.lists-stale", Severity: sev, Path: l.File,
			Message: msg + ": pending security fixes are invisible until apt update runs",
			Fix:     "check that apt-daily.timer runs (systemctl status apt-daily.timer) and that the mirror is reachable; `sudo apt update`"})
	}

	// Pending security updates: installed version < best version in a
	// security pocket for the same architecture.
	best := map[string]Pending{}
	for _, p := range e.glob(listsDir + "/*_Packages*") {
		base := filepath.Base(p)
		s := suiteOf(base)
		if !isSecuritySuite(s) {
			continue
		}
		scanPackages(e, p, func(name, ver, arch string) {
			inst, ok := dpkg[name+":"+arch]
			if !ok && arch == "all" {
				inst, ok = dpkg[name]
			}
			if !ok || CompareDebVersions(ver, inst.Version) <= 0 {
				return
			}
			key := name + ":" + inst.Arch
			if cur, seen := best[key]; seen && CompareDebVersions(cur.Available, ver) >= 0 {
				return
			}
			best[key] = Pending{Package: name, Installed: inst.Version, Available: ver, Suite: s}
		})
	}
	for _, v := range best {
		st.SecurityPending = append(st.SecurityPending, v)
	}
	sort.Slice(st.SecurityPending, func(i, j int) bool { return st.SecurityPending[i].Package < st.SecurityPending[j].Package })
	if n := len(st.SecurityPending); n > 0 {
		sev := findings.SevWarn
		if n >= ap.SecurityFail {
			sev = findings.SevFail
		}
		var names []string
		for i, p := range st.SecurityPending {
			if i == 12 {
				names = append(names, fmt.Sprintf("… +%d", n-i))
				break
			}
			names = append(names, p.Package+" "+p.Installed+" → "+p.Available)
		}
		c.Add(findings.Finding{Rule: "apt.security-pending", Severity: sev, Path: listsDir,
			Message: fmt.Sprintf("%d installed package(s) have a newer version in a security pocket: %s", n, strings.Join(names, ", ")),
			Fix:     "sudo apt update && sudo apt upgrade (or `sudo unattended-upgrade -v`); review held packages with `apt-mark showhold`"})
	} else if len(st.SecurityLists) > 0 {
		c.Add(findings.Finding{Rule: "apt.security-pending", Severity: findings.SevInfo, Path: listsDir,
			Message: "no pending updates from security pockets"})
	}

	// update-notifier's summary (Ubuntu): ESM-only fixes.
	if data, err := e.read("/var/lib/update-notifier/updates-available"); err == nil {
		if m := esmRe.FindSubmatch(data); m != nil {
			st.ESMSecurity, _ = strconv.Atoi(string(m[1]))
			c.Add(findings.Finding{Rule: "apt.esm-available", Severity: findings.SevInfo, Path: "/var/lib/update-notifier/updates-available",
				Message: fmt.Sprintf("%d additional security update(s) are only available with Ubuntu Pro / ESM", st.ESMSecurity),
				Fix:     "consider `pro attach` (free for personal use) to receive ESM security fixes for universe packages"})
		}
	}

	if entries, err := os.ReadDir(e.path("/var/lib/dpkg/updates")); err == nil && len(entries) > 0 {
		c.Add(findings.Finding{Rule: "apt.dpkg-interrupted", Severity: findings.SevWarn, Path: "/var/lib/dpkg/updates",
			Message: "a dpkg run was interrupted; unattended upgrades stop until it is finished",
			Fix:     "sudo dpkg --configure -a"})
	}
	for _, p := range dpkg {
		if p.Status != "installed" {
			c.Add(findings.Finding{Rule: "apt.dpkg-interrupted", Severity: findings.SevWarn, Path: "/var/lib/dpkg/status",
				Message: fmt.Sprintf("package %s is %s (an upgrade did not finish)", p.Name, p.Status),
				Fix:     "sudo dpkg --configure -a"})
		}
	}

	checkUnattended(e, ap, st, dpkg, c)

	// Reboot required.
	if fi, err := e.stat("/var/run/reboot-required"); err == nil {
		st.RebootRequired = true
		if data, err := e.read("/var/run/reboot-required.pkgs"); err == nil {
			for _, l := range strings.Fields(string(data)) {
				st.RebootPackages = appendUniq(st.RebootPackages, l)
			}
		}
		age := e.now.Sub(fi.ModTime())
		sev := findings.SevWarn
		if age > time.Duration(ap.RebootMaxDays)*24*time.Hour {
			sev = findings.SevFail
		}
		msg := "a reboot is required (pending for " + humanAge(age) + ")"
		if len(st.RebootPackages) > 0 {
			msg += " by " + strings.Join(st.RebootPackages, ", ")
		}
		c.Add(findings.Finding{Rule: "apt.reboot-required", Severity: sev, Path: "/var/run/reboot-required",
			Message: msg + ": installed fixes (kernel, libc, ...) are not active until then",
			Fix:     "schedule a reboot, or set Unattended-Upgrade::Automatic-Reboot with a maintenance window"})
	}
}

var esmRe = regexp.MustCompile(`(\d+) additional security updates? can be applied with ESM`)

// scanPackages streams a Packages index (plain or .gz).
func scanPackages(e *env, p string, fn func(name, ver, arch string)) {
	f, err := os.Open(e.path(p))
	if err != nil {
		return
	}
	defer f.Close()
	var r io.Reader = f
	switch {
	case strings.HasSuffix(p, ".gz"):
		gz, err := gzip.NewReader(f)
		if err != nil {
			return
		}
		defer gz.Close()
		r = gz
	case strings.HasSuffix(p, "_Packages"):
	default:
		return // .lz4/.xz indexes are not supported
	}
	_ = stanzas(io.LimitReader(r, 1<<30), []string{"Package", "Version", "Architecture"}, func(m map[string]string) {
		if m["Package"] != "" && m["Version"] != "" {
			fn(m["Package"], m["Version"], m["Architecture"])
		}
	})
}

var aptConfRe = regexp.MustCompile(`(?m)^\s*(APT::Periodic::[A-Za-z-]+)\s+"([^"]*)"\s*;`)

func checkUnattended(e *env, ap AptPolicy, st *AptState, dpkg map[string]dpkgPkg, c *findings.Collector) {
	u := &st.Unattended
	_, u.Installed = dpkg["unattended-upgrades"]
	periodic := map[string]string{}
	var origins string
	for _, p := range e.glob("/etc/apt/apt.conf.d/*") {
		data, err := e.read(p)
		if err != nil {
			continue
		}
		text := stripAptComments(string(data))
		for _, m := range aptConfRe.FindAllStringSubmatch(text, -1) {
			periodic[m[1]] = m[2]
		}
		if strings.Contains(text, "Unattended-Upgrade::Allowed-Origins") || strings.Contains(text, "Unattended-Upgrade::Origins-Pattern") {
			origins += text
		}
	}
	u.Enabled = periodic["APT::Periodic::Unattended-Upgrade"] != "" && periodic["APT::Periodic::Unattended-Upgrade"] != "0"
	low := strings.ToLower(origins)
	u.Security = strings.Contains(low, "-security") || strings.Contains(low, "label=debian-security")
	timer := "/etc/systemd/system/timers.target.wants/apt-daily-upgrade.timer"
	masked := false
	if t, err := os.Readlink(e.path("/etc/systemd/system/apt-daily-upgrade.timer")); err == nil && t == "/dev/null" {
		masked = true
	}
	u.TimerActive = e.exists(timer) && !masked
	stamp := "/var/lib/apt/periodic/unattended-upgrades-stamp"
	var lastAge time.Duration = -1
	if fi, err := e.stat(stamp); err == nil {
		u.LastRun = fi.ModTime().Format(time.RFC3339)
		lastAge = e.now.Sub(fi.ModTime())
	}

	sev := findings.SevWarn
	if !*ap.RequireUnattended {
		sev = findings.SevInfo
	}
	var problems []string
	if !u.Installed {
		problems = append(problems, "the unattended-upgrades package is not installed")
	}
	if !u.Enabled {
		problems = append(problems, `APT::Periodic::Unattended-Upgrade is not enabled`)
	}
	if u.Installed && !u.Security {
		problems = append(problems, "Allowed-Origins/Origins-Pattern has no security pocket")
	}
	if !u.TimerActive {
		if masked {
			problems = append(problems, "apt-daily-upgrade.timer is masked")
		} else {
			problems = append(problems, "apt-daily-upgrade.timer is not enabled")
		}
	}
	if u.Installed && u.Enabled {
		switch {
		case lastAge < 0:
			problems = append(problems, "it has never run ("+stamp+" is missing)")
		case lastAge > time.Duration(ap.UnattendedMaxDays)*24*time.Hour:
			problems = append(problems, "it last ran "+humanAge(lastAge)+" ago")
		}
	}
	if len(problems) > 0 {
		c.Add(findings.Finding{Rule: "apt.unattended", Severity: sev, Path: "/etc/apt/apt.conf.d",
			Message: "unattended security upgrades are not healthy: " + strings.Join(problems, "; "),
			Fix:     "sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades; check `systemctl status apt-daily-upgrade.timer` and /var/log/unattended-upgrades/"})
		return
	}
	c.Add(findings.Finding{Rule: "apt.unattended", Severity: findings.SevInfo, Path: "/etc/apt/apt.conf.d",
		Message: "unattended-upgrades enabled for the security pocket; last run " + humanAge(lastAge) + " ago"})
}

// stripAptComments removes // and # line comments and /* */ blocks.
func stripAptComments(s string) string {
	for {
		i := strings.Index(s, "/*")
		if i < 0 {
			break
		}
		j := strings.Index(s[i+2:], "*/")
		if j < 0 {
			s = s[:i]
			break
		}
		s = s[:i] + s[i+2+j+2:]
	}
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") {
			continue
		}
		if i := strings.Index(line, " //"); i >= 0 && strings.Count(line[:i], `"`)%2 == 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func humanAge(d time.Duration) string {
	switch {
	case d < 0:
		return "unknown"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

func orUnknown(s string) string {
	if s == "-security" || s == "" {
		return "<release>-security"
	}
	return s
}

func joinKeys(m map[string]bool) string {
	var k []string
	for s := range m {
		k = append(k, s)
	}
	sort.Strings(k)
	return strings.Join(k, ", ")
}

func appendUniq(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}
