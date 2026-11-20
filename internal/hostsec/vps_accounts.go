package hostsec

// vps group, part 2: sudoers NOPASSWD, authorized_keys hygiene and the
// listener allowlist (Дамагер's fresh-VPS checklist, 2026-11-12).

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

// ---- sudoers ----

type sudoLine struct {
	file string
	line int
	text string
}

// sudoersLines reads /etc/sudoers and its includes, joining "\" line
// continuations and dropping comments. It also returns unreadable files.
func sudoersLines(e *env) (lines []sudoLine, unreadable []string) {
	seen := map[string]bool{}
	var read func(p string, depth int)
	readDir := func(dir string, depth int) {
		seen[dir] = true
		names, err := openDir(e.path(dir))
		if err != nil {
			if e.exists(dir) {
				unreadable = append(unreadable, dir)
			}
			return
		}
		sort.Strings(names)
		for _, b := range names {
			if strings.Contains(b, ".") || strings.HasSuffix(b, "~") { // sudo skips these in includedir
				continue
			}
			read(path.Join(dir, b), depth+1)
		}
	}
	read = func(p string, depth int) {
		if depth > 8 || seen[p] {
			return
		}
		seen[p] = true
		b, err := e.read(p)
		if err != nil {
			if e.exists(p) {
				unreadable = append(unreadable, p)
			}
			return
		}
		raw := strings.Split(string(b), "\n")
		for i := 0; i < len(raw); i++ {
			start := i
			l := raw[i]
			for strings.HasSuffix(l, "\\") && i+1 < len(raw) {
				i++
				l = strings.TrimSuffix(l, "\\") + " " + raw[i]
			}
			t := strings.TrimSpace(l)
			for _, pre := range []string{"#includedir", "@includedir"} {
				if strings.HasPrefix(t, pre+" ") {
					readDir(strings.TrimSpace(t[len(pre):]), depth)
					t = ""
				}
			}
			for _, pre := range []string{"#include", "@include"} {
				if t != "" && strings.HasPrefix(t, pre+" ") {
					read(strings.TrimSpace(t[len(pre):]), depth+1)
					t = ""
				}
			}
			// "#1000 ALL=..." is a uid, not a comment.
			if strings.HasPrefix(t, "#") && !(len(t) > 1 && t[1] >= '0' && t[1] <= '9') {
				t = ""
			}
			if j := strings.Index(t, " #"); j >= 0 {
				t = strings.TrimSpace(t[:j])
			}
			if t != "" {
				lines = append(lines, sudoLine{p, start + 1, t})
			}
		}
	}
	read("/etc/sudoers", 0)
	if !seen["/etc/sudoers.d"] {
		// Also look at sudoers.d when /etc/sudoers itself is unreadable.
		readDir("/etc/sudoers.d", 0)
	}
	return lines, unreadable
}

var sudoTags = []string{"NOPASSWD:", "PASSWD:", "NOEXEC:", "EXEC:", "SETENV:", "NOSETENV:", "LOG_INPUT:", "NOLOG_INPUT:", "LOG_OUTPUT:", "NOLOG_OUTPUT:", "MAIL:", "NOMAIL:", "FOLLOW:", "NOFOLLOW:", "INTERCEPT:", "NOINTERCEPT:"}

// nopasswdCommands returns the commands of a user spec that run without a
// password, and whether one of them is ALL.
func nopasswdCommands(spec string, aliases map[string][]string) (cmds []string, all bool) {
	_, rhs, ok := strings.Cut(spec, "=")
	if !ok {
		return nil, false
	}
	nopass := false
	for _, item := range strings.Split(rhs, ",") {
		item = strings.TrimSpace(item)
		for {
			if strings.HasPrefix(item, "(") { // runas
				if j := strings.IndexByte(item, ')'); j > 0 {
					item = strings.TrimSpace(item[j+1:])
					continue
				}
			}
			tag := ""
			for _, t := range sudoTags {
				if strings.HasPrefix(item, t) {
					tag = t
					break
				}
			}
			if tag == "" {
				break
			}
			switch tag {
			case "NOPASSWD:":
				nopass = true
			case "PASSWD:":
				nopass = false
			}
			item = strings.TrimSpace(item[len(tag):])
		}
		if !nopass || item == "" {
			continue
		}
		cmds = append(cmds, item)
		if isSudoAll(item, aliases, 0) {
			all = true
		}
	}
	return cmds, all
}

func isSudoAll(item string, aliases map[string][]string, depth int) bool {
	item = strings.TrimPrefix(strings.TrimSpace(item), "!")
	if item == "ALL" {
		return true
	}
	if depth < 8 {
		for _, a := range aliases[item] {
			if isSudoAll(a, aliases, depth+1) {
				return true
			}
		}
	}
	return false
}

func checkSudoers(e *env, c *findings.Collector) {
	lines, unreadable := sudoersLines(e)
	if len(unreadable) > 0 {
		c.Add(findings.Finding{Rule: "host.sudoers-nopasswd", Severity: findings.SevInfo, Path: strings.Join(unreadable, ","),
			Message: "sudoers not readable without root (" + strings.Join(unreadable, ", ") + "); run with sudo or pass --root with a copy to check NOPASSWD"})
	}
	aliases := map[string][]string{}
	for _, l := range lines {
		if strings.HasPrefix(l.text, "Cmnd_Alias ") {
			for _, def := range strings.Split(strings.TrimPrefix(l.text, "Cmnd_Alias "), ":") {
				if name, val, ok := strings.Cut(def, "="); ok {
					for _, v := range strings.Split(val, ",") {
						aliases[strings.TrimSpace(name)] = append(aliases[strings.TrimSpace(name)], strings.TrimSpace(v))
					}
				}
			}
		}
	}
	for _, l := range lines {
		first := strings.Fields(l.text)[0]
		if strings.HasPrefix(first, "Defaults") || strings.HasSuffix(first, "_Alias") || !strings.Contains(l.text, "NOPASSWD") {
			continue
		}
		cmds, all := nopasswdCommands(l.text, aliases)
		if len(cmds) == 0 {
			continue
		}
		at := l.file + ":" + strconv.Itoa(l.line)
		if all {
			c.Add(findings.Finding{Rule: "host.sudoers-nopasswd", Severity: findings.SevWarn, Path: at, CWE: cwe("CWE-250", "CWE-269"),
				Message: first + " may run ALL commands as root without a password: anyone with that account's SSH key or a shell as it (e.g. a compromised service) is root",
				Fix:     "drop NOPASSWD (cloud-init writes it to /etc/sudoers.d/90-cloud-init-users) or limit it to specific commands; edit with sudo visudo -f FILE"})
			continue
		}
		c.Add(findings.Finding{Rule: "host.sudoers-nopasswd", Severity: findings.SevInfo, Path: at, CWE: cwe("CWE-250"),
			Message: first + " may run without a password only: " + strings.Join(cmds, ", ") + " (check none of them allows a shell escape)"})
	}
}

// ---- authorized_keys ----

type passwdEntry struct {
	user, home, shell string
	uid               int
}

func readPasswd(e *env) []passwdEntry {
	b, err := e.read("/etc/passwd")
	if err != nil {
		return nil
	}
	var out []passwdEntry
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Split(l, ":")
		if len(f) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(f[2])
		out = append(out, passwdEntry{f[0], f[5], f[6], uid})
	}
	return out
}

func loginShell(sh string) bool {
	b := path.Base(sh)
	return sh != "" && b != "nologin" && b != "false" && b != "sync"
}

// splitKeyLine separates the options of an authorized_keys line from the
// key (options may contain quoted spaces).
func splitKeyLine(l string) (opts, typ, blob string) {
	isType := func(s string) bool {
		return strings.HasPrefix(s, "ssh-") || strings.HasPrefix(s, "ecdsa-") || strings.HasPrefix(s, "sk-")
	}
	f := strings.Fields(l)
	if len(f) >= 2 && isType(f[0]) {
		return "", f[0], f[1]
	}
	inQ := false
	for i, r := range l {
		switch {
		case r == '"':
			inQ = !inQ
		case (r == ' ' || r == '\t') && !inQ:
			rest := strings.Fields(l[i:])
			if len(rest) >= 2 && isType(rest[0]) {
				return l[:i], rest[0], rest[1]
			}
			return l[:i], "", ""
		}
	}
	return l, "", ""
}

// rsaBits returns the modulus size of an ssh-rsa public key blob.
func rsaBits(blob string) int {
	b, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return 0
	}
	next := func() []byte {
		if len(b) < 4 {
			return nil
		}
		n := binary.BigEndian.Uint32(b)
		if uint64(n) > uint64(len(b)-4) {
			return nil
		}
		v := b[4 : 4+n]
		b = b[4+n:]
		return v
	}
	if string(next()) != "ssh-rsa" {
		return 0
	}
	_ = next() // e
	n := next()
	if n == nil {
		return 0
	}
	return new(big.Int).SetBytes(n).BitLen()
}

func hasKeyOpt(opts, name string) bool {
	for _, o := range strings.Split(opts, ",") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(o)), name+"=") {
			return true
		}
	}
	return false
}

func checkAuthorizedKeys(e *env, c *findings.Collector) {
	type acct struct{ user, home string }
	accts := []acct{{"root", "/root"}}
	for _, p := range readPasswd(e) {
		if p.uid == 0 || (p.uid >= 1000 && p.uid < 65534 && loginShell(p.shell) && p.home != "" && p.home != "/") {
			if p.uid == 0 && p.home == "/root" {
				continue
			}
			accts = append(accts, acct{p.user, p.home})
		}
	}
	seenBlob := map[string]string{} // blob -> first location
	for _, a := range accts {
		for _, name := range []string{".ssh/authorized_keys", ".ssh/authorized_keys2"} {
			p := path.Join(a.home, name)
			b, err := e.read(p)
			if err != nil {
				if e.exists(p) {
					c.Add(findings.Finding{Rule: "host.authorized-keys-hygiene", Severity: findings.SevInfo, Path: p,
						Message: "not readable without root; run with sudo to check " + a.user + "'s keys"})
				}
				continue
			}
			unrestricted := 0
			for i, raw := range strings.Split(string(b), "\n") {
				l := strings.TrimSpace(raw)
				if l == "" || l[0] == '#' {
					continue
				}
				at := p + ":" + strconv.Itoa(i+1)
				opts, typ, blob := splitKeyLine(l)
				if typ == "" {
					continue
				}
				switch {
				case typ == "ssh-dss":
					c.Add(findings.Finding{Rule: "host.authorized-keys-hygiene", Severity: findings.SevWarn, Path: at, CWE: cwe("CWE-326", "CWE-327"),
						Message: a.user + ": DSA key (ssh-dss, 1024-bit, removed from OpenSSH 9.8+)", Fix: "replace it with an ed25519 key (ssh-keygen -t ed25519) and remove the line"})
				case typ == "ssh-rsa":
					if bits := rsaBits(blob); bits > 0 && bits < 2048 {
						c.Add(findings.Finding{Rule: "host.authorized-keys-hygiene", Severity: findings.SevWarn, Path: at, CWE: cwe("CWE-326"),
							Message: fmt.Sprintf("%s: RSA key is %d bits (< 2048)", a.user, bits), Fix: "replace it with an ed25519 key (or RSA ≥ 3072) and remove the line"})
					}
				}
				if first, dup := seenBlob[blob]; dup {
					c.Add(findings.Finding{Rule: "host.authorized-keys-hygiene", Severity: findings.SevWarn, Path: at, CWE: cwe("CWE-284"),
						Message: a.user + ": the same key is already authorized at " + first + " (duplicate or a key shared between accounts)", Fix: "remove the duplicate; give each person/automation its own key"})
				} else {
					seenBlob[blob] = at
				}
				if !hasKeyOpt(opts, "from") && !hasKeyOpt(opts, "command") {
					if a.user == "root" {
						c.Add(findings.Finding{Rule: "host.authorized-keys-hygiene", Severity: findings.SevWarn, Path: at, CWE: cwe("CWE-284", "CWE-250"),
							Message: "root: key without from= or command= restriction (full root shell from any address)",
							Fix:     "log in as a sudo user instead of root, or restrict the key: from=\"ADMIN_IP/32\" (and command=\"...\" for automation); PermitRootLogin prohibit-password|no"})
					} else {
						unrestricted++
					}
				}
			}
			if unrestricted > 0 {
				c.Add(findings.Finding{Rule: "host.authorized-keys-hygiene", Severity: findings.SevInfo, Path: p,
					Message: fmt.Sprintf("%s: %d key(s) without from=/command= restriction", a.user, unrestricted)})
			}
		}
	}
}

// ---- listeners policy ----

func vpsListeners(e *env, opt Options) ([]Listener, error) {
	if len(opt.SS) > 0 {
		return ParseSS(string(opt.SS))
	}
	ls, err := procListeners(e)
	if err == nil {
		attachProcesses(e, ls)
	}
	return ls, err
}

func checkListenersPolicy(e *env, opt Options, pol *Policy, v *VpsState, c *findings.Collector) {
	allowed := opt.ListenAllowed
	src := "--listen-policy"
	if allowed == nil && pol != nil && pol.Listen != nil {
		allowed, src = pol.Listen.Allowed, "[host.listen]"
	}
	ls, err := vpsListeners(e, opt)
	if err != nil {
		return
	}
	lo, hi := ephemeralRange(e)
	clientUDP := mustSpecs(DefaultExpectedPublic)
	specs := mustSpecs(allowed)
	var inv []string
	for _, l := range dedupe(ls) {
		if l.Scope == "loopback" {
			continue
		}
		if l.Proto == "udp" && ((l.Port >= lo && l.Port <= hi) || matchAny(clientUDP, l.Proto, l.Port)) {
			continue // client sockets (DHCP, mDNS, ephemeral)
		}
		who := ""
		if l.Process != "" {
			who = " (" + l.Process + ")"
		}
		v.Listeners = append(v.Listeners, l.Endpoint()+who)
		if allowed == nil {
			inv = append(inv, l.Endpoint()+who)
			continue
		}
		if !matchAny(specs, l.Proto, l.Port) {
			c.Add(findings.Finding{Rule: "host.listeners-policy", Severity: findings.SevWarn, Path: "listen:" + l.Endpoint(), CWE: cwe("CWE-1327", "CWE-284"),
				Message: fmt.Sprintf("%s%s listens outside loopback but is not in the allowed ports of %s", l.Endpoint(), who, src),
				Fix:     "bind the service to 127.0.0.1 / a private interface, stop it, or add the port to the policy if it is meant to be public"})
		}
	}
	if allowed == nil && len(inv) > 0 {
		sort.Strings(inv)
		c.Add(findings.Finding{Rule: "host.listeners-policy", Severity: findings.SevInfo, Path: "listen", CWE: cwe("CWE-1327"),
			Message: "non-loopback listeners (no policy; add [host.listen] allowed = [...] or --listen-policy FILE): " + strings.Join(inv, ", ")})
	}
}
