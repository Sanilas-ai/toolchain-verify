package hostsec

// The vps check group (`toolchain-verify host vps`, alias `--profile vps`)
// audits a freshly provisioned internet-facing server: template SSH host
// keys, the effective sshd configuration, kernel/auto-update hygiene,
// firewall and brute-force protection, time sync and the git CVE of
// November 2026. Like the rest of hostsec it only parses files and the
// optional command outputs passed in Options; it executes nothing.

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

// VpsState summarizes the vps group.
type VpsState struct {
	Hostname    string            `json:"hostname,omitempty"`
	FirstBoot   string            `json:"first_boot,omitempty"`
	FirstBootBy string            `json:"first_boot_source,omitempty"`
	HostKeys    []HostKey         `json:"host_keys,omitempty"`
	Sshd        map[string]string `json:"sshd_effective,omitempty"`
	SshdSource  string            `json:"sshd_source,omitempty"` // "sshd -T" or "config"
	SSHPorts    []int             `json:"ssh_ports,omitempty"`
	Firewall    string            `json:"firewall,omitempty"`
	BruteForce  []string          `json:"bruteforce_protection,omitempty"`
	NTP         string            `json:"ntp,omitempty"`
	Git         string            `json:"git_version,omitempty"`
}

// HostKey is one /etc/ssh/ssh_host_*_key.pub.
type HostKey struct {
	Path    string `json:"path"`
	Type    string `json:"type"`
	Comment string `json:"comment,omitempty"`
	ModTime string `json:"mtime"`
}

func cwe(ids ...string) []string { return ids }

func checkVps(e *env, opt Options, rep *Report, dpkg map[string]dpkgPkg, c *findings.Collector) {
	v := &VpsState{}
	rep.Vps = v
	v.Hostname = hostname(e)
	checkHostKeys(e, v, c)
	eff := checkSshd(e, opt, v, c)
	checkKernelStale(e, rep, dpkg, c)
	checkAutoUpdates(e, dpkg, c)
	fwOK, ufw := checkFirewall(e, opt, v, c)
	exposed := checkSSHExposed(e, opt, v, eff, fwOK, ufw, c)
	checkBruteForce(e, v, dpkg, exposed, ufw, eff, c)
	checkNTP(e, opt, v, dpkg, c)
	checkGitCVE(e, opt, v, dpkg, c)
}

func hostname(e *env) string {
	if b, err := e.read("/etc/hostname"); err == nil {
		return strings.TrimSpace(string(b))
	}
	if b, err := e.read("/proc/sys/kernel/hostname"); err == nil {
		return strings.TrimSpace(string(b))
	}
	return ""
}

// firstBoot returns when this machine was installed or first booted.
// cloud-init's instance-id is written on the first boot of this instance;
// the installer log dir and machine-id are fallbacks (machine-id can be
// baked into a bad image, so it comes last).
func firstBoot(e *env) (time.Time, string) {
	for _, p := range []string{"/var/lib/cloud/data/instance-id", "/var/log/installer", "/etc/machine-id"} {
		if fi, err := e.stat(p); err == nil {
			return fi.ModTime(), p
		}
	}
	return time.Time{}, ""
}

const sshdRef = "https://man.openbsd.org/sshd_config"

func checkHostKeys(e *env, v *VpsState, c *findings.Collector) {
	keys := e.glob("/etc/ssh/ssh_host_*_key.pub")
	if len(keys) == 0 {
		if e.exists("/etc/ssh/sshd_config") {
			c.Add(findings.Finding{Rule: "host.ssh-hostkeys-template", Severity: findings.SevInfo, Path: "/etc/ssh",
				Message: "no ssh_host_*_key.pub found (unreadable or not generated yet)"})
		}
		return
	}
	boot, bootSrc := firstBoot(e)
	if !boot.IsZero() {
		v.FirstBoot, v.FirstBootBy = boot.UTC().Format(time.RFC3339), bootSrc
	}
	host := v.Hostname
	short, _, _ := strings.Cut(host, ".")
	fix := "regenerate the host keys on this machine: sudo rm /etc/ssh/ssh_host_*; sudo ssh-keygen -A; sudo systemctl restart ssh; then publish the new fingerprints (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub) and update known_hosts on clients"
	hasEd25519 := false
	for _, p := range keys {
		fi, err := e.stat(p)
		if err != nil {
			continue
		}
		b, _ := e.read(p)
		f := strings.Fields(string(b))
		k := HostKey{Path: p, ModTime: fi.ModTime().UTC().Format(time.RFC3339)}
		if len(f) > 0 {
			k.Type = f[0]
		}
		if len(f) > 2 {
			k.Comment = strings.Join(f[2:], " ")
		}
		v.HostKeys = append(v.HostKeys, k)
		base := path.Base(p)
		if k.Type == "ssh-ed25519" || strings.Contains(base, "_ed25519_") {
			hasEd25519 = true
		}
		if k.Type == "ssh-dss" || strings.Contains(base, "_dsa_") {
			c.Add(findings.Finding{Rule: "host.ssh-hostkeys-template", Severity: findings.SevFail, Path: p, CWE: cwe("CWE-327"),
				Message: "DSA host key present: ssh-dss is broken (1024-bit) and removed from OpenSSH 9.8+",
				Fix:     "sudo rm /etc/ssh/ssh_host_dsa_key*; drop any HostKey line for it from sshd_config; sudo ssh-keygen -A", Refs: []string{sshdRef}})
		}
		var why []string
		if at := strings.LastIndexByte(k.Comment, '@'); at >= 0 && host != "" {
			kh := k.Comment[at+1:]
			if kh != host && kh != short {
				why = append(why, fmt.Sprintf("comment %q names another host (this host is %q)", k.Comment, host))
			}
		}
		if !boot.IsZero() && fi.ModTime().Before(boot.Add(-time.Hour)) {
			why = append(why, fmt.Sprintf("key is older (%s) than the first boot of this instance (%s, from %s)",
				fi.ModTime().UTC().Format("2006-01-02 15:04"), boot.UTC().Format("2006-01-02 15:04"), bootSrc))
		}
		if len(why) > 0 {
			c.Add(findings.Finding{Rule: "host.ssh-hostkeys-template", Severity: findings.SevWarn, Path: p, CWE: cwe("CWE-1394", "CWE-321"),
				Message: "host key looks inherited from the provider image (every VM from the template may share the private key, enabling MITM): " + strings.Join(why, "; "),
				Fix:     fix, Refs: []string{sshdRef}})
		}
	}
	if !hasEd25519 {
		c.Add(findings.Finding{Rule: "host.ssh-hostkeys-template", Severity: findings.SevWarn, Path: "/etc/ssh", CWE: cwe("CWE-327"),
			Message: "no ed25519 host key", Fix: "sudo ssh-keygen -A (creates the missing ed25519 key); sudo systemctl restart ssh"})
	}
}

// sshdSetting is one value with its origin.
type sshdSetting struct {
	value string
	at    string // file:line
}

// SshdEffective is the global sshd configuration with first-match-wins
// semantics. Values are lower-case keyword -> first value; Ports and
// ListenAddresses are cumulative.
type SshdEffective struct {
	Values   map[string]sshdSetting
	Shadowed map[string][]sshdSetting // later values that sshd ignores
	Ports    []int
	Listen   []string
	FromT    bool
}

func (s *SshdEffective) get(k string) (string, string) {
	if v, ok := s.Values[k]; ok {
		return v.value, v.at
	}
	return "", ""
}

// ParseSshdT parses `sshd -T` output.
func ParseSshdT(out string) *SshdEffective {
	s := &SshdEffective{Values: map[string]sshdSetting{}, Shadowed: map[string][]sshdSetting{}, FromT: true}
	for _, line := range strings.Split(out, "\n") {
		k, val, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		k = strings.ToLower(k)
		val = strings.TrimSpace(val)
		switch k {
		case "port":
			if n, err := strconv.Atoi(val); err == nil {
				s.Ports = append(s.Ports, n)
			}
		case "listenaddress":
			s.Listen = append(s.Listen, val)
		}
		if _, dup := s.Values[k]; !dup {
			s.Values[k] = sshdSetting{strings.ToLower(val), "sshd -T"}
		}
	}
	return s
}

// ParseSshdConfig evaluates sshd_config like sshd does for global
// settings: the first value of a keyword wins, Include is expanded in
// place (globs in lexical order, relative to /etc/ssh), and lines after
// a Match are conditional and not applied globally (a Match inside an
// included file ends with that file).
func parseSshdConfig(e *env, file string) *SshdEffective {
	s := &SshdEffective{Values: map[string]sshdSetting{}, Shadowed: map[string][]sshdSetting{}}
	var walk func(p string, depth int, inMatch bool)
	walk = func(p string, depth int, inMatch bool) {
		if depth > 16 {
			return
		}
		b, err := e.read(p)
		if err != nil {
			return
		}
		match := inMatch
		for i, raw := range strings.Split(string(b), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || line[0] == '#' {
				continue
			}
			k, val := splitSshdLine(line)
			if k == "" {
				continue
			}
			at := p + ":" + strconv.Itoa(i+1)
			switch k {
			case "match":
				match = true
				continue
			case "include":
				for _, pat := range strings.Fields(val) {
					if !strings.HasPrefix(pat, "/") {
						pat = "/etc/ssh/" + pat
					}
					for _, inc := range e.glob(pat) {
						walk(inc, depth+1, match)
					}
				}
				continue
			}
			if match {
				continue
			}
			switch k {
			case "port":
				if n, err := strconv.Atoi(val); err == nil {
					s.Ports = append(s.Ports, n)
				}
			case "listenaddress":
				s.Listen = append(s.Listen, val)
			}
			if _, set := s.Values[k]; set {
				s.Shadowed[k] = append(s.Shadowed[k], sshdSetting{strings.ToLower(val), at})
				continue
			}
			s.Values[k] = sshdSetting{strings.ToLower(val), at}
		}
	}
	walk(file, 0, false)
	return s
}

func splitSshdLine(line string) (string, string) {
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return strings.ToLower(line), ""
	}
	k := strings.ToLower(line[:i])
	v := strings.TrimLeft(line[i:], " \t=")
	return k, strings.Trim(strings.TrimSpace(v), `"`)
}

func checkSshd(e *env, opt Options, v *VpsState, c *findings.Collector) *SshdEffective {
	var s *SshdEffective
	switch {
	case len(opt.SshdT) > 0:
		s = ParseSshdT(string(opt.SshdT))
		v.SshdSource = "sshd -T"
	case e.exists("/etc/ssh/sshd_config"):
		s = parseSshdConfig(e, "/etc/ssh/sshd_config")
		v.SshdSource = "config"
	default:
		return nil
	}
	if len(s.Ports) == 0 {
		s.Ports = []int{22}
	}
	v.SSHPorts = s.Ports
	v.Sshd = map[string]string{}
	for _, k := range []string{"passwordauthentication", "permitrootlogin", "kbdinteractiveauthentication", "pubkeyauthentication", "maxauthtries"} {
		if val, _ := s.get(k); val != "" {
			v.Sshd[k] = val
		}
	}
	explain := func(k, def string) (string, string) {
		val, at := s.get(k)
		if val == "" {
			return def, "not set anywhere, OpenSSH default"
		}
		where := at
		if sh := s.Shadowed[k]; len(sh) > 0 {
			var ign []string
			for _, x := range sh {
				ign = append(ign, fmt.Sprintf("%s (%s)", x.at, x.value))
			}
			where += "; later values are ignored because the first one wins: " + strings.Join(ign, ", ")
		}
		return val, where
	}
	pw, pwAt := explain("passwordauthentication", "yes")
	if pw == "yes" {
		c.Add(findings.Finding{Rule: "host.sshd-effective", Severity: findings.SevFail, Path: "sshd:passwordauthentication", CWE: cwe("CWE-309", "CWE-307"),
			Message: "effective PasswordAuthentication yes (" + pwAt + "): the server accepts password guessing from the internet",
			Fix:     "after installing your key, put `PasswordAuthentication no` in a drop-in that sorts first (e.g. /etc/ssh/sshd_config.d/00-hardening.conf) or fix 50-cloud-init.conf; then sudo sshd -t && sudo systemctl reload ssh; verify with sudo sshd -T | grep -E 'passwordauth|permitroot'",
			Refs:    []string{sshdRef}})
	}
	root, rootAt := explain("permitrootlogin", "prohibit-password")
	if root == "yes" {
		c.Add(findings.Finding{Rule: "host.sshd-effective", Severity: findings.SevFail, Path: "sshd:permitrootlogin", CWE: cwe("CWE-250", "CWE-284"),
			Message: "effective PermitRootLogin yes (" + rootAt + "): root can log in with a password",
			Fix:     "set `PermitRootLogin prohibit-password` (or `no` after creating a sudo user) in the first-sorting drop-in; sudo sshd -t && sudo systemctl reload ssh",
			Refs:    []string{sshdRef}})
	}
	if pw != "yes" && root != "yes" {
		c.Add(findings.Finding{Rule: "host.sshd-effective", Severity: findings.SevInfo, Path: "sshd", CWE: cwe("CWE-309"),
			Message: fmt.Sprintf("effective PasswordAuthentication %s, PermitRootLogin %s (from %s)", pw, root, v.SshdSource)})
	}
	if !s.FromT {
		c.Add(findings.Finding{Rule: "host.sshd-effective", Severity: findings.SevInfo, Path: "/etc/ssh/sshd_config",
			Message: "evaluated from the config files (first value wins, Include expanded, Match blocks ignored); pass --sshd-t with `sudo sshd -T` output for the authoritative view"})
	}
	return s
}

func newestKernelImage(dpkg map[string]dpkgPkg) (release, version string) {
	for key, p := range dpkg {
		if strings.Contains(key, ":") {
			continue
		}
		if m := kernelPkgRe.FindStringSubmatch(p.Name); m != nil && p.Status == "installed" {
			if version == "" || CompareDebVersions(p.Version, version) > 0 {
				release, version = m[1], p.Version
			}
		}
	}
	return
}

func checkKernelStale(e *env, rep *Report, dpkg map[string]dpkgPkg, c *findings.Collector) {
	k := rep.Kernel
	if k == nil {
		k = runningKernel(e)
	}
	var why []string
	if k != nil {
		if rel, ver := newestKernelImage(dpkg); rel != "" && rel != k.Release {
			running := ""
			for _, p := range dpkg {
				if m := kernelPkgRe.FindStringSubmatch(p.Name); m != nil && m[1] == k.Release {
					running = p.Version
				}
			}
			if running == "" || CompareDebVersions(ver, running) > 0 {
				why = append(why, fmt.Sprintf("running %s but %s (%s) is installed", k.Release, rel, ver))
			}
		}
		if rep.Apt != nil {
			for _, p := range rep.Apt.SecurityPending {
				if strings.HasPrefix(p.Package, "linux-image") {
					why = append(why, "security update available for "+p.Package+" "+p.Available)
					break
				}
			}
		}
	}
	for _, p := range []string{"/var/run/reboot-required", "/run/reboot-required"} {
		if e.exists(p) {
			msg := p + " exists"
			if b, err := e.read(p + ".pkgs"); err == nil && len(bytes.TrimSpace(b)) > 0 {
				msg += " (" + strings.Join(strings.Fields(string(b)), ", ") + ")"
			}
			why = append(why, msg)
			break
		}
	}
	if len(why) == 0 {
		return
	}
	rel := ""
	if k != nil {
		rel = k.Release
	}
	c.Add(findings.Finding{Rule: "host.kernel-stale", Severity: findings.SevWarn, Path: "kernel:" + rel, CWE: cwe("CWE-1395"),
		Message: "the running kernel is not the newest one, so its fixes are not active: " + strings.Join(why, "; "),
		Fix:     "sudo apt update && sudo apt full-upgrade, then sudo reboot in a maintenance window; check uname -r afterwards"})
}

func checkAutoUpdates(e *env, dpkg map[string]dpkgPkg, c *findings.Collector) {
	var why []string
	if _, ok := dpkg["unattended-upgrades"]; !ok {
		why = append(why, "unattended-upgrades is not installed")
	}
	periodic := map[string]string{}
	for _, p := range e.glob("/etc/apt/apt.conf.d/*") {
		if b, err := e.read(p); err == nil {
			for _, m := range aptConfRe.FindAllStringSubmatch(stripAptComments(string(b)), -1) {
				periodic[m[1]] = m[2]
			}
		}
	}
	const auto = "/etc/apt/apt.conf.d/20auto-upgrades"
	if !e.exists(auto) {
		why = append(why, auto+" is missing")
	}
	if u := periodic["APT::Periodic::Unattended-Upgrade"]; u == "" || u == "0" {
		why = append(why, `APT::Periodic::Unattended-Upgrade is "`+u+`"`)
	}
	if u := periodic["APT::Periodic::Update-Package-Lists"]; u == "" || u == "0" {
		why = append(why, `APT::Periodic::Update-Package-Lists is "`+u+`"`)
	}
	if len(why) == 0 {
		return
	}
	c.Add(findings.Finding{Rule: "host.no-auto-updates", Severity: findings.SevWarn, Path: auto, CWE: cwe("CWE-1395"),
		Message: "automatic security updates are off: " + strings.Join(why, "; "),
		Fix:     "sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades (writes 20auto-upgrades with both values \"1\")"})
}

var (
	nftInputDropRe = regexp.MustCompile(`(?s)hook\s+input\b[^}]*?policy\s+(drop|reject)\b`)
	iptInputDropRe = regexp.MustCompile(`(?m)^:INPUT\s+DROP\b|^-A INPUT\b.*-j\s+(DROP|REJECT)\s*$`)
)

// checkFirewall decides whether some firewall has a default-deny input
// policy: ufw, nftables (`nft list ruleset` via --nft, or an enabled
// /etc/nftables.conf), or iptables-persistent rules.
func checkFirewall(e *env, opt Options, v *VpsState, c *findings.Collector) (bool, *Ufw) {
	u := readUfw(e, opt.UfwStatus)
	switch {
	case u != nil && u.Enabled && (u.DefaultIncoming == "deny" || u.DefaultIncoming == "reject"):
		v.Firewall = "ufw (default " + u.DefaultIncoming + ")"
	case len(opt.Nft) > 0 && nftInputDropRe.Match(opt.Nft):
		v.Firewall = "nftables ruleset (input policy drop)"
	case e.exists("/etc/systemd/system/sysinit.target.wants/nftables.service") && func() bool {
		b, err := e.read("/etc/nftables.conf")
		return err == nil && nftInputDropRe.Match(b)
	}():
		v.Firewall = "nftables.service with /etc/nftables.conf (input policy drop)"
	case func() bool {
		for _, p := range []string{"/etc/iptables/rules.v4", "/etc/iptables/rules.v6"} {
			if b, err := e.read(p); err == nil && iptInputDropRe.Match(b) {
				return true
			}
		}
		return false
	}():
		v.Firewall = "iptables-persistent (INPUT drop)"
	}
	if v.Firewall != "" {
		return true, u
	}
	var seen []string
	if u != nil {
		state := "inactive"
		if u.Enabled {
			state = "active, default incoming " + unknownIfEmpty(u.DefaultIncoming)
		}
		seen = append(seen, "ufw "+state)
	} else {
		seen = append(seen, "ufw not installed")
	}
	if e.exists("/etc/nftables.conf") {
		seen = append(seen, "/etc/nftables.conf has no input drop policy or nftables.service is not enabled")
	}
	c.Add(findings.Finding{Rule: "host.firewall-off", Severity: findings.SevFail, Path: "firewall", CWE: cwe("CWE-284", "CWE-1327"),
		Message: "no firewall with a default-deny input policy (" + strings.Join(seen, "; ") + "); every listening service is reachable from the internet",
		Fix:     "sudo ufw allow OpenSSH (or limit it to your IP: sudo ufw allow from ADDR to any port 22 proto tcp) && sudo ufw default deny incoming && sudo ufw enable; keep the provider console open in case you lock yourself out"})
	return false, u
}

// checkSSHExposed reports sshd listening on all addresses. It returns
// whether ssh is reachable from anywhere (as far as the files tell).
func checkSSHExposed(e *env, opt Options, v *VpsState, s *SshdEffective, fwOK bool, u *Ufw, c *findings.Collector) bool {
	ports := []int{22}
	if s != nil && len(s.Ports) > 0 {
		ports = s.Ports
	}
	var ls []Listener
	var err error
	if len(opt.SS) > 0 {
		ls, err = ParseSS(string(opt.SS))
	} else {
		ls, err = procListeners(e)
	}
	var wild []string
	if err == nil && len(ls) > 0 {
		for _, l := range ls {
			if l.Proto != "tcp" || l.Scope != "all" {
				continue
			}
			for _, p := range ports {
				if l.Port == p {
					wild = append(wild, l.Endpoint())
				}
			}
		}
	} else if s != nil {
		all := len(s.Listen) == 0
		for _, a := range s.Listen {
			h := a
			if strings.HasPrefix(h, "[") {
				h = strings.Trim(strings.SplitN(h, "]", 2)[0], "[")
			} else if strings.Count(h, ":") == 1 {
				h, _, _ = strings.Cut(h, ":")
			}
			if h == "0.0.0.0" || h == "::" || h == "*" {
				all = true
			}
		}
		if all {
			for _, p := range ports {
				wild = append(wild, fmt.Sprintf("*:%d/tcp (from sshd config)", p))
			}
		}
	}
	if len(wild) == 0 {
		return false
	}
	sort.Strings(wild)
	restricted := false
	if fwOK && u != nil && u.Enabled && u.Source != "" {
		restricted = true
		for _, r := range u.Rules {
			for _, p := range ports {
				if r.allows() && r.matches("tcp", p) && r.fromAnywhere() {
					restricted = false
				}
			}
		}
	}
	if restricted {
		c.Add(findings.Finding{Rule: "host.ssh-exposed", Severity: findings.SevInfo, Path: "listen:" + strings.Join(wild, ","), CWE: cwe("CWE-1327"),
			Message: "sshd listens on all addresses, but ufw only allows it from specific sources"})
		return false
	}
	c.Add(findings.Finding{Rule: "host.ssh-exposed", Severity: findings.SevWarn, Path: "listen:" + strings.Join(wild, ","), CWE: cwe("CWE-1327"),
		Message: "sshd listens on all addresses and is reachable from anywhere: " + strings.Join(wild, ", "),
		Fix:     "restrict port 22 to your admin addresses or a VPN (sudo ufw allow from ADDR to any port 22 proto tcp; or ListenAddress on a WireGuard/Tailscale interface); keys only, plus fail2ban/crowdsec"})
	return true
}

var bruteForcePkgs = []string{"fail2ban", "sshguard", "crowdsec", "crowdsec-firewall-bouncer-iptables", "crowdsec-firewall-bouncer-nftables"}

func checkBruteForce(e *env, v *VpsState, dpkg map[string]dpkgPkg, exposed bool, u *Ufw, s *SshdEffective, c *findings.Collector) {
	for _, p := range bruteForcePkgs {
		if _, ok := dpkg[p]; ok {
			v.BruteForce = append(v.BruteForce, p)
		}
	}
	for _, unit := range []string{"fail2ban.service", "sshguard.service", "crowdsec.service"} {
		if e.exists("/etc/systemd/system/multi-user.target.wants/" + unit) {
			v.BruteForce = append(v.BruteForce, unit)
		}
	}
	if u != nil && u.Enabled {
		for _, r := range u.Rules {
			for _, p := range v.SSHPorts {
				if r.Action == "limit" && r.matches("tcp", p) {
					v.BruteForce = append(v.BruteForce, "ufw limit "+strconv.Itoa(p)+"/tcp")
				}
			}
		}
	}
	if len(v.BruteForce) > 0 || s == nil {
		return
	}
	sev := findings.SevInfo
	msg := "no fail2ban, sshguard, crowdsec or ufw limit rule"
	if exposed {
		sev = findings.SevWarn
		msg += " while sshd is reachable from the internet"
		if pw, _ := s.get("passwordauthentication"); pw == "no" {
			msg += " (passwords are off, so this is mostly log noise and MaxStartups exhaustion)"
		}
	}
	c.Add(findings.Finding{Rule: "host.no-bruteforce-protection", Severity: sev, Path: "sshd", CWE: cwe("CWE-307"),
		Message: msg,
		Fix:     "sudo apt install fail2ban (the sshd jail is on by default on Ubuntu) or crowdsec + a firewall bouncer; or sudo ufw limit 22/tcp"})
}

func checkNTP(e *env, opt Options, v *VpsState, dpkg map[string]dpkgPkg, c *findings.Collector) {
	fix := "sudo timedatectl set-ntp true (systemd-timesyncd) or install chrony; check timedatectl timesync-status"
	if len(opt.Timedatectl) > 0 {
		kv := map[string]string{}
		for _, line := range strings.Split(string(opt.Timedatectl), "\n") {
			if k, val, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
				kv[k] = strings.TrimSpace(val)
			}
		}
		v.NTP = "NTP=" + kv["NTP"] + " NTPSynchronized=" + kv["NTPSynchronized"]
		if kv["NTPSynchronized"] == "no" || kv["NTP"] == "no" {
			c.Add(findings.Finding{Rule: "host.ntp-unsynced", Severity: findings.SevWarn, Path: "timedatectl", CWE: cwe("CWE-778"),
				Message: "clock is not NTP-synchronized (" + v.NTP + "): log timestamps, TLS/OCSP validity, TOTP and Kerberos break as the clock drifts", Fix: fix})
		}
		return
	}
	if e.exists("/run/systemd/timesync/synchronized") {
		v.NTP = "systemd-timesyncd synchronized"
		return
	}
	for _, p := range []string{"chrony", "ntp", "ntpsec", "openntpd"} {
		if _, ok := dpkg[p]; ok {
			v.NTP = p + " installed (sync state unknown)"
			c.Add(findings.Finding{Rule: "host.ntp-unsynced", Severity: findings.SevInfo, Path: "timedatectl", CWE: cwe("CWE-778"),
				Message: p + " is installed; pass --timedatectl with `timedatectl show` output to check NTPSynchronized"})
			return
		}
	}
	if _, ok := dpkg["systemd-timesyncd"]; ok || e.exists("/etc/systemd/system/sysinit.target.wants/systemd-timesyncd.service") {
		v.NTP = "systemd-timesyncd not synchronized"
		c.Add(findings.Finding{Rule: "host.ntp-unsynced", Severity: findings.SevWarn, Path: "/run/systemd/timesync/synchronized", CWE: cwe("CWE-778"),
			Message: "systemd-timesyncd has not reported a synchronized clock (/run/systemd/timesync/synchronized is missing)", Fix: fix})
		return
	}
	v.NTP = "no time sync daemon found"
	c.Add(findings.Finding{Rule: "host.ntp-unsynced", Severity: findings.SevWarn, Path: "timedatectl", CWE: cwe("CWE-778"),
		Message: "no NTP client found (systemd-timesyncd, chrony, ntp, ntpsec)", Fix: fix})
}

// Git releases that fix CVE-2026-111760, per maintenance series.
var gitFixed111760 = map[[2]int]int{{2, 50}: 2, {2, 51}: 3, {2, 52}: 1, {2, 53}: 1, {2, 54}: 1, {2, 55}: 1, {2, 56}: 1}

var gitVerRe = regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?`)

// upstreamGit extracts 2.34.1 from "git version 2.34.1" or the dpkg
// version "1:2.34.1-1ubuntu1.15".
func upstreamGit(s string) (maj, min, patch int, ok bool) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ':'); i >= 0 && i < 3 {
		s = s[i+1:]
	}
	m := gitVerRe.FindStringSubmatch(s)
	if m == nil {
		return 0, 0, 0, false
	}
	maj, _ = strconv.Atoi(m[1])
	min, _ = strconv.Atoi(m[2])
	patch, _ = strconv.Atoi(m[3])
	return maj, min, patch, true
}

// GitVulnerable111760 reports whether an upstream git version lacks the
// CVE-2026-111760 fix.
func GitVulnerable111760(maj, min, patch int) bool {
	if maj != 2 {
		return maj < 2
	}
	if min > 56 {
		return false
	}
	fixed, ok := gitFixed111760[[2]int{maj, min}]
	if !ok {
		return true // < 2.50 has no upstream fix release
	}
	return patch < fixed
}

func checkGitCVE(e *env, opt Options, v *VpsState, dpkg map[string]dpkgPkg, c *findings.Collector) {
	src, raw := "", ""
	if len(opt.GitVersion) > 0 {
		src, raw = "git --version", strings.TrimSpace(string(opt.GitVersion))
	} else if p, ok := dpkg["git"]; ok {
		src, raw = "dpkg git", p.Version
	} else {
		return
	}
	v.Git = raw
	maj, min, patch, ok := upstreamGit(raw)
	if !ok || !GitVulnerable111760(maj, min, patch) {
		return
	}
	refs := []string{"https://github.com/git/git/security/advisories/GHSA-vp2w-7xxj-jvxr", "https://github.blog/open-source/git/git-security-vulnerabilities-announced-7/"}
	if src == "dpkg git" && debianChangelogMentions(e, "/usr/share/doc/git/changelog.Debian.gz", "CVE-2026-111760") {
		c.Add(findings.Finding{Rule: "host.git-cve-2026-111760", Severity: findings.SevInfo, Path: "/usr/share/doc/git/changelog.Debian.gz", CWE: cwe("CWE-197", "CWE-59"),
			Message: fmt.Sprintf("git %s is older than 2.56.1, but the distro changelog lists CVE-2026-111760 as fixed (backport)", raw), Refs: refs})
		return
	}
	c.Add(findings.Finding{Rule: "host.git-cve-2026-111760", Severity: findings.SevWarn, Path: "git:" + raw, CWE: cwe("CWE-197", "CWE-59"),
		Message: fmt.Sprintf("git %d.%d.%d (%s) is vulnerable to CVE-2026-111760 (High, CVSS 8.0): a malicious repository can run code during `git clone --recurse-submodules` (fixed in 2.56.1, 2.55.1, 2.54.1, 2.53.1, 2.52.1, 2.51.3, 2.50.2); distro backports are not visible in the version, check `apt changelog git`", maj, min, patch, src),
		Fix:     "upgrade git (sudo apt update && sudo apt install --only-upgrade git, or the git-core PPA / a source build for 2.56.1); until then never clone untrusted repositories with --recurse-submodules or submodule update --recursive",
		Refs:    refs})
}

func debianChangelogMentions(e *env, p, needle string) bool {
	f, err := os.Open(e.path(p))
	if err != nil {
		return false
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return false
	}
	defer gz.Close()
	b, _ := io.ReadAll(io.LimitReader(gz, 1<<20)) // newest entries come first
	return bytes.Contains(b, []byte(needle))
}

func unknownIfEmpty(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
