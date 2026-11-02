package hostsec

import (
	"strings"
	"testing"

	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

// /proc/net fixtures: 0.0.0.0:22, 127.0.0.1:631, 0.0.0.0:8765,
// 192.168.1.5:6379, established 0.0.0.0:22 peer (ignored).
const procTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1002 1 0000000000000000 100 0 0 10 0
   2: 00000000:223D 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1003 1 0000000000000000 100 0 0 10 0
   3: 0501A8C0:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 1004 1 0000000000000000 100 0 0 10 0
   4: 0501A8C0:0016 0A01A8C0:D431 01 00000000:00000000 00:00000000 00000000     0        0 1005 1 0000000000000000 100 0 0 10 0
`

// [::]:22, [::1]:5432, [::]:3389.
const procTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2001 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:1538 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   113        0 2002 1 0000000000000000 100 0 0 10 0
   2: 00000000000000000000000000000000:0D3D 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   117        0 2003 1 0000000000000000 100 0 0 10 0
`

// 0.0.0.0:5353 (mdns), 0.0.0.0:41234 (ephemeral), 0.0.0.0:137.
const procUDP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  1: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000   114        0 3001 2 0000000000000000 0
  2: 00000000:A0F2 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 3002 2 0000000000000000 0
  3: 00000000:0089 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 3003 2 0000000000000000 0
`

func netTree(t *testing.T) *tree {
	tr := newTree(t)
	tr.write("/proc/net/tcp", procTCP)
	tr.write("/proc/net/tcp6", procTCP6)
	tr.write("/proc/net/udp", procUDP)
	tr.write("/proc/sys/net/ipv4/ip_local_port_range", "32768\t60999\n")
	tr.write("/proc/4242/comm", "uvicorn\n")
	tr.symlink("/proc/4242/fd/3", "socket:[1003]")
	tr.symlink("/proc/4242/fd/4", "/dev/null")
	tr.write("/etc/ufw/ufw.conf", "# comment\nENABLED=yes\nLOGLEVEL=low\n")
	tr.write("/etc/default/ufw", "IPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\n")
	return tr
}

const userRules = `*filter
:ufw-user-input - [0:0]
### RULES ###

### tuple ### allow tcp 22 0.0.0.0/0 any 192.168.1.0/24 in
-A ufw-user-input -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT

### tuple ### allow tcp 3389 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 3389 -j ACCEPT

### tuple ### limit_log tcp 2222 0.0.0.0/0 any 0.0.0.0/0 in

### tuple ### allow udp 137,138 0.0.0.0/0 any 0.0.0.0/0 Samba - in

### tuple ### allow any 6000:6010 0.0.0.0/0 any 0.0.0.0/0 in_wlan0

### tuple ### deny tcp 8765 0.0.0.0/0 any 0.0.0.0/0 in

### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 out
### END RULES ###
`

func TestProcListeners(t *testing.T) {
	tr := netTree(t)
	rep := run(t, tr, nil, Options{Net: true})
	got := map[string]Listener{}
	for _, l := range rep.Net.Listeners {
		got[l.Endpoint()] = l
	}
	for _, want := range []string{"0.0.0.0:22/tcp", "[::]:22/tcp", "127.0.0.1:631/tcp", "0.0.0.0:8765/tcp", "192.168.1.5:6379/tcp", "[::1]:5432/tcp", "[::]:3389/tcp", "0.0.0.0:5353/udp", "0.0.0.0:137/udp", "0.0.0.0:41202/udp"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing listener %s; got %v", want, keys(got))
		}
	}
	if len(got) != 10 {
		t.Errorf("listeners = %v", keys(got))
	}
	if l := got["0.0.0.0:8765/tcp"]; l.Process != "uvicorn" || l.PID != 4242 || l.UID != 1000 {
		t.Errorf("8765 = %+v", l)
	}
	if got["127.0.0.1:631/tcp"].Scope != "loopback" || got["[::1]:5432/tcp"].Scope != "loopback" || got["192.168.1.5:6379/tcp"].Scope != "address" {
		t.Error("scopes are wrong")
	}
}

func keys(m map[string]Listener) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestReconcileUserRules(t *testing.T) {
	tr := netTree(t)
	tr.write("/etc/ufw/user.rules", userRules)
	tr.write("/etc/ufw/user6.rules", "### tuple ### allow tcp 22 ::/0 any ::/0 in\n")
	rep := run(t, tr, &Policy{Net: &NetPolicy{ExpectedPublic: []string{"3389/tcp"}}}, Options{Net: true})
	if rep.Net.Ufw.Source != "rules" || !rep.Net.Ufw.Enabled || rep.Net.Ufw.DefaultIncoming != "deny" {
		t.Fatalf("ufw = %+v", rep.Net.Ufw)
	}
	// 22: v6 rule allows from anywhere (preferred over the LAN-only v4 rule).
	one(t, rep, "net.exposed", findings.SevWarn, "0.0.0.0:22/tcp, [::]:22/tcp")
	// 3389 allowed from anywhere but expected.
	one(t, rep, "net.exposed", findings.SevInfo, "[::]:3389")
	// 8765 only has a deny rule: unneeded wildcard bind.
	f := one(t, rep, "net.unneeded-bind", findings.SevWarn, "uvicorn pid 4242")
	if !strings.Contains(f.Path, "8765/tcp") {
		t.Errorf("path = %q", f.Path)
	}
	// 137/udp allowed by the Samba rule from anywhere.
	one(t, rep, "net.exposed", findings.SevWarn, "0.0.0.0:137")
	// 5353/udp: default expected, no rule.
	one(t, rep, "net.unneeded-bind", findings.SevInfo, "0.0.0.0:5353")
	// Redis on a LAN address: sensitive.
	one(t, rep, "net.address-listener", findings.SevWarn, "192.168.1.5:6379")
	// Ephemeral UDP and loopback are skipped.
	for _, f := range rep.Findings {
		if strings.Contains(f.Message, "41202") || strings.Contains(f.Message, ":631") || strings.Contains(f.Message, "5432") {
			t.Errorf("unexpected finding %s: %s", f.Rule, f.Message)
		}
	}
	// Allow rules without listeners: 2222 (limit), 138/udp, 6000:6010.
	unused := find(rep, "net.allow-unused")
	var paths []string
	for _, u := range unused {
		paths = append(paths, u.Path)
	}
	joined := strings.Join(paths, "\n")
	for _, want := range []string{"2222", "6000:6010"} {
		if !strings.Contains(joined, want) {
			t.Errorf("allow-unused lacks %s: %s", want, joined)
		}
	}
	if strings.Contains(joined, "8765") || strings.Contains(joined, " 80 ") {
		t.Errorf("deny/out rules reported as unused: %s", joined)
	}
	if !rep.OK {
		t.Errorf("no fail expected:\n%s", dump(rep))
	}
}

func TestReconcileSensitiveExposedFails(t *testing.T) {
	tr := netTree(t)
	tr.write("/proc/net/tcp", procTCP+"   5: 00000000:0947 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1006 1 0000000000000000 100 0 0 10 0\n")
	tr.write("/etc/ufw/user.rules", "### tuple ### allow any any 0.0.0.0/0 any 0.0.0.0/0 in\n")
	rep := run(t, tr, nil, Options{Net: true})
	one(t, rep, "net.exposed", findings.SevFail, "0.0.0.0:2375/tcp")
	if rep.OK {
		t.Error("docker API exposed to anywhere must fail")
	}
}

func TestFirewallOff(t *testing.T) {
	tr := netTree(t)
	tr.write("/etc/ufw/ufw.conf", "ENABLED=no\n")
	tr.write("/proc/net/tcp", procTCP+"   5: 00000000:2CAA 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1006 1 0000000000000000 100 0 0 10 0\n")
	rep := run(t, tr, nil, Options{Net: true})
	one(t, rep, "net.ufw-inactive", findings.SevWarn, "not enabled")
	one(t, rep, "net.public-listener", findings.SevWarn, "8765")
	one(t, rep, "net.public-listener", findings.SevFail, "0.0.0.0:11434/tcp")
	none(t, rep, "net.allow-unused")

	tr2 := netTree(t)
	tr2.write("/etc/default/ufw", "DEFAULT_INPUT_POLICY=\"ACCEPT\"\n")
	tr2.write("/etc/ufw/user.rules", "")
	rep = run(t, tr2, nil, Options{Net: true})
	one(t, rep, "net.ufw-default-allow", findings.SevWarn, "default incoming policy is allow")

	tr3 := netTree(t)
	for _, p := range []string{"/etc/ufw/ufw.conf", "/etc/default/ufw"} {
		tr3.write(p, "")
	}
	rep = run(t, tr3, nil, Options{Net: true})
	_ = rep
	tr4 := newTree(t)
	tr4.write("/proc/net/tcp", procTCP)
	rep = run(t, tr4, nil, Options{Net: true})
	one(t, rep, "net.no-firewall", findings.SevWarn, "not installed")
}

func TestRulesUnreadable(t *testing.T) {
	tr := netTree(t) // no user.rules: same as permission denied
	rep := run(t, tr, nil, Options{Net: true})
	one(t, rep, "net.ufw-rules-unreadable", findings.SevInfo, "--ufw-status")
	one(t, rep, "net.public-listener", findings.SevWarn, "reachability is unknown")
	one(t, rep, "net.public-listener", findings.SevInfo, "0.0.0.0:5353")
}

const ufwStatusVerbose = `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    192.168.1.0/24             # ssh from LAN
3389                       ALLOW IN    Anywhere
OpenSSH                    LIMIT IN    Anywhere
Samba                      ALLOW IN    192.168.1.0/24
192.168.1.5 6379/tcp       ALLOW IN    192.168.1.7
8765/tcp on wlan0          DENY IN     Anywhere
10.0.0.0/8                 ALLOW IN    Anywhere
443/tcp                    ALLOW OUT   Anywhere
22/tcp (v6)                ALLOW IN    Anywhere (v6)
`

func appsTree(t *testing.T) *tree {
	tr := netTree(t)
	tr.write("/etc/ufw/applications.d/openssh-server", "[OpenSSH]\ntitle=Secure shell server\ndescription=x\nports=22/tcp\n")
	tr.write("/etc/ufw/applications.d/samba", "[Samba]\ntitle=LanManager-like file and printer server for Unix\nports=137,138/udp|139,445/tcp\n")
	return tr
}

func TestParseUfwStatus(t *testing.T) {
	tr := appsTree(t)
	apps := ufwApps(&env{root: tr.root})
	u := &Ufw{}
	if err := parseUfwStatus(ufwStatusVerbose, apps, u); err != nil {
		t.Fatal(err)
	}
	if !u.Enabled || u.DefaultIncoming != "deny" {
		t.Errorf("ufw = %+v", u)
	}
	want := []struct {
		action, from, to, iface string
		port                    int
		proto                   string
		v6                      bool
	}{
		{"allow", "192.168.1.0/24", "any", "", 22, "tcp", false},
		{"allow", "any", "any", "", 3389, "udp", false},
		{"limit", "any", "any", "", 22, "tcp", false},
		{"allow", "192.168.1.0/24", "any", "", 445, "tcp", false},
		{"allow", "192.168.1.7", "192.168.1.5", "", 6379, "tcp", false},
		{"deny", "any", "any", "wlan0", 8765, "tcp", false},
		{"allow", "any", "10.0.0.0/8", "", 0, "", false},
		{"allow", "any", "any", "", 22, "tcp", true},
	}
	if len(u.Rules) != len(want) {
		t.Fatalf("rules = %d: %+v", len(u.Rules), u.Rules)
	}
	for i, w := range want {
		r := u.Rules[i]
		if r.Action != w.action || r.From != w.from || r.To != w.to || r.Iface != w.iface || r.V6 != w.v6 {
			t.Errorf("rule %d = %+v, want %+v", i, r, w)
		}
		if w.port != 0 && !r.matches(w.proto, w.port) {
			t.Errorf("rule %d (%s) does not match %d/%s", i, r.Raw, w.port, w.proto)
		}
	}
	if u.Rules[0].matches("udp", 22) {
		t.Error("22/tcp matched udp")
	}
	if !u.Rules[3].matches("udp", 138) || u.Rules[3].matches("tcp", 138) {
		t.Error("Samba profile ports are wrong")
	}

	// numbered output, inactive, unknown profile.
	u = &Ufw{}
	if err := parseUfwStatus("Status: active\n\n     To                         Action      From\n     --                         ------      ----\n[ 1] 22/tcp                     ALLOW IN    Anywhere\n[ 2] 5000:5010/tcp              ALLOW IN    10.0.0.0/8\n", apps, u); err != nil {
		t.Fatal(err)
	}
	if len(u.Rules) != 2 || !u.Rules[1].matches("tcp", 5005) || u.Rules[1].From != "10.0.0.0/8" {
		t.Errorf("numbered rules = %+v", u.Rules)
	}
	u = &Ufw{}
	if err := parseUfwStatus("Status: inactive\n", apps, u); err != nil || u.Enabled {
		t.Errorf("inactive: %v %+v", err, u)
	}
	if err := parseUfwStatus("Status: active\nTo  Action  From\n--  ------  ----\nNginx Full                 ALLOW IN    Anywhere\n", apps, &Ufw{}); err == nil {
		t.Error("unknown profile must be reported")
	}
	if err := parseUfwStatus("ERROR: You need to be root to run this script\n", apps, &Ufw{}); err == nil {
		t.Error("missing Status line must be an error")
	}
}

func TestReconcileUfwStatus(t *testing.T) {
	tr := appsTree(t)
	status := strings.Replace(ufwStatusVerbose, "10.0.0.0/8                 ALLOW IN    Anywhere\n", "", 1)
	rep := run(t, tr, nil, Options{Net: true, UfwStatus: []byte(status)})
	if rep.Net.Ufw.Source != "status" {
		t.Fatalf("source = %q", rep.Net.Ufw.Source)
	}
	none(t, rep, "net.ufw-rules-unreadable")
	// 3389 open from anywhere; not expected by default.
	one(t, rep, "net.exposed", findings.SevWarn, "[::]:3389")
	// 22: the (v6) rule allows it from anywhere.
	one(t, rep, "net.exposed", findings.SevWarn, "0.0.0.0:22")
	// 137/udp from the LAN via Samba.
	one(t, rep, "net.exposed", findings.SevInfo, "ufw allows it from 192.168.1.0/24")
	one(t, rep, "net.unneeded-bind", findings.SevWarn, "8765")
}

func TestParseSS(t *testing.T) {
	out := `Netid State  Recv-Q Send-Q   Local Address:Port  Peer Address:Port Process
udp   UNCONN 0      0              0.0.0.0:5353       0.0.0.0:*     users:(("avahi-daemon",pid=812,fd=12))
udp   UNCONN 0      0        127.0.0.53%lo:53         0.0.0.0:*
tcp   LISTEN 0      4096           0.0.0.0:18765      0.0.0.0:*     users:(("python3",pid=9001,fd=7),("python3",pid=9002,fd=7))
tcp   LISTEN 0      128               [::]:22            [::]:*
tcp   LISTEN 0      50                   *:3389             *:*     users:(("xrdp",pid=1300,fd=11))
tcp   LISTEN 0      511      192.168.1.5%wlan0:80         0.0.0.0:*
tcp   ESTAB  0      0          192.168.1.5:22   192.168.1.7:51000
`
	ls, err := ParseSS(out)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Listener{}
	for _, l := range ls {
		got[l.Endpoint()] = l
	}
	for _, w := range []string{"0.0.0.0:5353/udp", "127.0.0.53:53/udp", "0.0.0.0:18765/tcp", "[::]:22/tcp", "*:3389/tcp", "192.168.1.5:80/tcp"} {
		if _, ok := got[w]; !ok {
			t.Errorf("missing %s in %v", w, keys(got))
		}
	}
	if len(got) != 6 {
		t.Errorf("listeners = %v", keys(got))
	}
	if l := got["0.0.0.0:18765/tcp"]; l.Process != "python3" || l.PID != 9001 {
		t.Errorf("18765 = %+v", l)
	}
	if got["*:3389/tcp"].Scope != "all" || got["127.0.0.53:53/udp"].Scope != "loopback" {
		t.Error("scopes")
	}
	// -H output without the Netid column (ss -tlnH).
	ls, err = ParseSS("LISTEN 0 4096 0.0.0.0:8765 0.0.0.0:*\n")
	if err != nil || len(ls) != 1 || ls[0].Proto != "tcp" || ls[0].Port != 8765 {
		t.Errorf("no-netid: %v %+v", err, ls)
	}
	if _, err := ParseSS("garbage line here\n"); err == nil {
		t.Error("garbage must be an error")
	}
}

func TestReconcileFromSS(t *testing.T) {
	tr := appsTree(t)
	ss := `tcp LISTEN 0 50 *:3389 *:* users:(("xrdp",pid=1300,fd=11))` + "\n"
	rep := run(t, tr, &Policy{Net: &NetPolicy{ExpectedPublic: []string{"3389/tcp"}}}, Options{Net: true, SS: []byte(ss), UfwStatus: []byte(ufwStatusVerbose)})
	if rep.Net.Source != "ss" || len(rep.Net.Listeners) != 1 {
		t.Fatalf("net = %+v", rep.Net)
	}
	f := one(t, rep, "net.exposed", findings.SevInfo, "xrdp pid 1300")
	_ = f
	one(t, rep, "net.allow-unused", findings.SevInfo, "nothing listens")
}
