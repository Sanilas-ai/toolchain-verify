package hostsec

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

// sshString encodes an SSH wire-format string.
func sshString(b []byte) []byte {
	out := make([]byte, 4, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	return append(out, b...)
}

// fakeRSA builds a syntactically valid ssh-rsa blob with a bits-sized
// "modulus" of filler bytes (not a real key).
func fakeRSA(bits int) string {
	n := make([]byte, bits/8+1) // leading 0 like an mpint
	n[1] = 0x80
	for i := 2; i < len(n); i++ {
		n[i] = byte(i)
	}
	blob := append(sshString([]byte("ssh-rsa")), sshString([]byte{1, 0, 1})...)
	blob = append(blob, sshString(n)...)
	return base64.StdEncoding.EncodeToString(blob)
}

func fakeEd25519(seed byte) string {
	k := make([]byte, 32)
	for i := range k {
		k[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(append(sshString([]byte("ssh-ed25519")), sshString(k)...))
}

func TestRSABits(t *testing.T) {
	for _, bits := range []int{1024, 2048, 4096} {
		if got := rsaBits(fakeRSA(bits)); got != bits {
			t.Errorf("rsaBits(%d) = %d", bits, got)
		}
	}
	if rsaBits("!!") != 0 || rsaBits(fakeEd25519(1)) != 0 {
		t.Error("garbage must give 0")
	}
}

func TestSshdKbdInteractivePAM(t *testing.T) {
	tr := newTree(t)
	tr.write("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\nPermitRootLogin prohibit-password\nUsePAM yes\n")
	tr.write("/etc/ssh/sshd_config.d/10-legacy.conf", "ChallengeResponseAuthentication yes\n")
	rep := runVps(t, tr, Options{})
	f := one(t, rep, "host.sshd-effective", findings.SevFail, "KbdInteractiveAuthentication yes")
	if !strings.Contains(f.Message, "10-legacy.conf:1") || !hasCWE(f, "CWE-309") {
		t.Errorf("alias evidence: %s", f.Message)
	}
	// Unset KbdInteractive is yes by default, still a password with PAM.
	tr2 := newTree(t)
	tr2.write("/etc/ssh/sshd_config", "PasswordAuthentication no\nUsePAM yes\n")
	one(t, runVps(t, tr2, Options{}), "host.sshd-effective", findings.SevFail, "OpenSSH default")
	// Without PAM keyboard-interactive has no password backend: no fail.
	tr3 := newTree(t)
	tr3.write("/etc/ssh/sshd_config", "PasswordAuthentication no\nKbdInteractiveAuthentication yes\n")
	for _, f := range find(runVps(t, tr3, Options{}), "host.sshd-effective") {
		if f.Severity == findings.SevFail {
			t.Errorf("no PAM: %+v", f)
		}
	}
	// sshd -T reports the alias under kbdinteractiveauthentication.
	rep = runVps(t, tr3, Options{SshdT: []byte("passwordauthentication no\nkbdinteractiveauthentication yes\nusepam yes\npermitrootlogin no\n")})
	one(t, rep, "host.sshd-effective", findings.SevFail, "UsePAM yes (sshd -T)")
}

func TestSudoersNopasswd(t *testing.T) {
	tr := newTree(t)
	tr.write("/etc/sudoers", "Defaults env_reset\n# comment NOPASSWD: ALL\nroot ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\nCmnd_Alias EVERYTHING = ALL\n@includedir /etc/sudoers.d\n")
	tr.write("/etc/sudoers.d/90-cloud-init-users", "# Created by cloud-init\nubuntu ALL=(ALL) NOPASSWD:ALL\n")
	tr.write("/etc/sudoers.d/20-backup", "backup ALL=(root) NOPASSWD: /usr/bin/rsync, \\\n    /usr/bin/systemctl restart backup\n")
	tr.write("/etc/sudoers.d/30-alias", "ops ALL=(ALL) NOPASSWD: EVERYTHING\n")
	tr.write("/etc/sudoers.d/40-mixed", "dev ALL=(ALL) NOPASSWD: /usr/bin/apt update, PASSWD: ALL\n")
	tr.write("/etc/sudoers.d/README.dpkg-old", "evil ALL=(ALL) NOPASSWD: ALL\n") // sudo skips names with a dot
	rep := runVps(t, tr, Options{})
	w := one(t, rep, "host.sudoers-nopasswd", findings.SevWarn, "ubuntu may run ALL")
	if w.Path != "/etc/sudoers.d/90-cloud-init-users:2" || !hasCWE(w, "CWE-250") || !hasCWE(w, "CWE-269") {
		t.Errorf("cloud-init: %+v", w)
	}
	one(t, rep, "host.sudoers-nopasswd", findings.SevWarn, "ops may run ALL")
	i := one(t, rep, "host.sudoers-nopasswd", findings.SevInfo, "backup may run without a password only")
	if !strings.Contains(i.Message, "systemctl restart backup") {
		t.Errorf("continuation: %s", i.Message)
	}
	one(t, rep, "host.sudoers-nopasswd", findings.SevInfo, "dev may run without a password only: /usr/bin/apt update")
	for _, f := range find(rep, "host.sudoers-nopasswd") {
		if strings.Contains(f.Message, "evil") || strings.Contains(f.Message, "root may") {
			t.Errorf("unexpected: %+v", f)
		}
	}
}

func TestAuthorizedKeysHygiene(t *testing.T) {
	tr := newTree(t)
	tr.write("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\nadmin:x:1000:1000::/home/admin:/bin/bash\nsvc:x:1001:1001::/home/svc:/usr/sbin/nologin\n")
	shared := fakeEd25519(7)
	tr.write("/root/.ssh/authorized_keys", "ssh-ed25519 "+shared+" admin@laptop\nfrom=\"198.51.100.7/32\" ssh-ed25519 "+fakeEd25519(9)+" restricted\n")
	tr.write("/home/admin/.ssh/authorized_keys", strings.Join([]string{
		"# my keys",
		"ssh-ed25519 " + shared + " admin@laptop", // shared with root
		"ssh-rsa " + fakeRSA(1024) + " old",       // short RSA
		"ssh-rsa " + fakeRSA(4096) + " ok",        // fine
		"ssh-dss " + fakeEd25519(3) + " dsa",      // DSA (blob content irrelevant)
		`command="/usr/bin/rrsync /srv",no-pty ssh-ed25519 ` + fakeEd25519(11) + " backup",
		"ssh-rsa " + fakeRSA(4096) + " ok-dup", // same blob as line 4
	}, "\n")+"\n")
	tr.write("/home/svc/.ssh/authorized_keys", "ssh-dss AAAA ignored-nologin\n")
	rep := runVps(t, tr, Options{})
	one(t, rep, "host.authorized-keys-hygiene", findings.SevWarn, "root: key without from= or command=")
	if f := find(rep, "host.authorized-keys-hygiene"); strings.Count(sevs(f), "warn:/root/") != 1 {
		t.Errorf("restricted root key flagged: %s", sevs(f))
	}
	d := one(t, rep, "host.authorized-keys-hygiene", findings.SevWarn, "already authorized at /root/.ssh/authorized_keys:1")
	if d.Path != "/home/admin/.ssh/authorized_keys:2" {
		t.Errorf("dup path: %s", d.Path)
	}
	one(t, rep, "host.authorized-keys-hygiene", findings.SevWarn, "RSA key is 1024 bits")
	one(t, rep, "host.authorized-keys-hygiene", findings.SevWarn, "admin: DSA key")
	one(t, rep, "host.authorized-keys-hygiene", findings.SevWarn, "already authorized at /home/admin/.ssh/authorized_keys:4")
	one(t, rep, "host.authorized-keys-hygiene", findings.SevInfo, "admin: 5 key(s) without from=/command=")
	for _, f := range rep.Findings {
		if strings.Contains(f.Path, "/home/svc") || strings.Contains(f.Message, "AAAA") {
			t.Errorf("nologin account or key material in output: %+v", f)
		}
	}
}

const policyTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   113        0 1002 1 0000000000000000 100 0 0 10 0
   2: 00000000:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 1003 1 0000000000000000 100 0 0 10 0
`

const policyUDP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 00000000:04AA 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 3001 2 0000000000000000 0
   1: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 3002 2 0000000000000000 0
   2: 00000000:9C40 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 3003 2 0000000000000000 0
`

func TestListenersPolicy(t *testing.T) {
	tr := newTree(t)
	tr.write("/proc/net/tcp", policyTCP) // 22, 127.0.0.1:5432, 3306
	tr.write("/proc/net/udp", policyUDP) // 1194, 68 (DHCP), 40000 (ephemeral)
	rep := runVps(t, tr, Options{})
	inv := one(t, rep, "host.listeners-policy", findings.SevInfo, "no policy")
	if !strings.Contains(inv.Message, "0.0.0.0:22/tcp") || !strings.Contains(inv.Message, "0.0.0.0:3306/tcp") || !strings.Contains(inv.Message, "0.0.0.0:1194/udp") ||
		strings.Contains(inv.Message, "5432") || strings.Contains(inv.Message, ":68/") || strings.Contains(inv.Message, "40000") {
		t.Errorf("inventory: %s", inv.Message)
	}
	rep = runVps(t, tr, Options{ListenAllowed: []string{"22/tcp", "1194/udp"}})
	w := one(t, rep, "host.listeners-policy", findings.SevWarn, "0.0.0.0:3306/tcp")
	if !hasCWE(w, "CWE-1327") || len(find(rep, "host.listeners-policy")) != 1 {
		t.Errorf("policy: %s", sevs(find(rep, "host.listeners-policy")))
	}
	// Manifest policy and ss -tlnp input.
	ss := "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nLISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=812,fd=3))\nLISTEN 0 511 [::]:8080 [::]:* users:((\"node\",pid=901,fd=20))\nLISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*\n"
	rep, err := Run(&Policy{Listen: &ListenPolicy{Allowed: []string{"22/tcp"}}}, Options{Root: tr.root, Vps: true, SS: []byte(ss), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	w = one(t, rep, "host.listeners-policy", findings.SevWarn, "[::]:8080/tcp (node)")
	if !strings.Contains(w.Message, "[host.listen]") {
		t.Errorf("source: %s", w.Message)
	}
	if _, err := Run(&Policy{Listen: &ListenPolicy{Allowed: []string{"22/sctp"}}}, Options{Root: tr.root, Vps: true}); err == nil {
		t.Error("bad port spec must be rejected")
	}
}
