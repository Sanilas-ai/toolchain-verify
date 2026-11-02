package hostsec

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

// NetState is the listener inventory and the firewall view.
type NetState struct {
	Source    string     `json:"source"` // "/proc/net" or "ss"
	Listeners []Listener `json:"listeners"`
	Ufw       *Ufw       `json:"ufw,omitempty"`
}

// service groups the IPv4/IPv6 sockets of one proto/port.
type service struct {
	proto     string
	port      int
	endpoints []string
	procs     []string
	all       bool // some socket listens on all interfaces
}

func (s *service) name() string { return fmt.Sprintf("%d/%s", s.port, s.proto) }

func (s *service) who() string {
	if len(s.procs) == 0 {
		return ""
	}
	return " (" + strings.Join(s.procs, ", ") + ")"
}

func checkNet(e *env, np *NetPolicy, opt Options, rep *Report, c *findings.Collector) {
	if np == nil {
		np = &NetPolicy{}
	}
	ns := &NetState{Source: "/proc/net"}
	rep.Net = ns
	var ls []Listener
	var err error
	if len(opt.SS) > 0 {
		ns.Source = "ss"
		ls, err = ParseSS(string(opt.SS))
	} else {
		ls, err = procListeners(e)
		if err == nil {
			attachProcesses(e, ls)
		}
	}
	if err != nil {
		c.Add(findings.Finding{Rule: "net.unavailable", Severity: findings.SevWarn, Path: ns.Source,
			Message: "cannot list listening sockets: " + err.Error()})
		return
	}
	ns.Listeners = dedupe(ls)
	ns.Ufw = readUfw(e, opt.UfwStatus)

	expected := mustSpecs(append(append([]string(nil), DefaultExpectedPublic...), np.ExpectedPublic...))
	sensitive := mustSpecs(DefaultSensitive)
	if np.Sensitive != nil {
		sensitive = mustSpecs(np.Sensitive)
	}
	ephLo, ephHi := ephemeralRange(e)

	// Group by proto/port.
	svcs := map[string]*service{}
	var order []string
	for _, l := range ns.Listeners {
		if l.Scope == "loopback" {
			continue
		}
		if l.Proto == "udp" && !np.IncludeEphemeralUDP && l.Port >= ephLo && l.Port <= ephHi {
			continue
		}
		k := fmt.Sprintf("%s/%d", l.Proto, l.Port)
		s := svcs[k]
		if s == nil {
			s = &service{proto: l.Proto, port: l.Port}
			svcs[k] = s
			order = append(order, k)
		}
		s.endpoints = appendUniq(s.endpoints, l.Endpoint())
		if l.Process != "" {
			s.procs = appendUniq(s.procs, fmt.Sprintf("%s pid %d", l.Process, l.PID))
		}
		if l.Scope == "all" {
			s.all = true
		}
	}
	sort.Strings(order)

	u := ns.Ufw
	known := u != nil && u.Source != ""
	firewallOff := u == nil || !u.Enabled || u.DefaultIncoming == "allow"
	switch {
	case u == nil:
		c.Add(findings.Finding{Rule: "net.no-firewall", Severity: findings.SevWarn, Path: "/etc/ufw",
			Message: "ufw is not installed; listeners cannot be reconciled with a host firewall",
			Fix:     "install and enable ufw (sudo apt install ufw && sudo ufw default deny incoming && sudo ufw enable) or check nftables/iptables manually"})
	case !u.Enabled:
		c.Add(findings.Finding{Rule: "net.ufw-inactive", Severity: findings.SevWarn, Path: "/etc/ufw/ufw.conf",
			Message: "ufw is installed but not enabled: every non-loopback listener is reachable from the network",
			Fix:     "sudo ufw default deny incoming && sudo ufw allow <needed ports> && sudo ufw enable"})
	case u.DefaultIncoming == "allow":
		c.Add(findings.Finding{Rule: "net.ufw-default-allow", Severity: findings.SevWarn, Path: "/etc/default/ufw",
			Message: "ufw's default incoming policy is allow: rules only add exceptions to an open host",
			Fix:     "sudo ufw default deny incoming"})
	}
	if u != nil && u.Note != "" {
		c.Add(findings.Finding{Rule: "net.ufw-rules-unreadable", Severity: findings.SevInfo, Path: "/etc/ufw/user.rules", Message: u.Note})
	}

	for _, k := range order {
		s := svcs[k]
		exp := matchAny(expected, s.proto, s.port)
		sens := matchAny(sensitive, s.proto, s.port)
		where := strings.Join(s.endpoints, ", ")
		if !s.all {
			// Bound to specific addresses (LAN, docker bridge, ...).
			if sens && !exp {
				c.Add(findings.Finding{Rule: "net.address-listener", Severity: findings.SevWarn, Path: "listen:" + s.name(),
					Message: fmt.Sprintf("sensitive service listens on non-loopback address(es) %s%s", where, s.who()),
					Fix:     "bind it to 127.0.0.1 unless other hosts need it"})
			} else {
				c.Add(findings.Finding{Rule: "net.address-listener", Severity: findings.SevInfo, Path: "listen:" + s.name(),
					Message: fmt.Sprintf("listens on specific address(es) %s%s", where, s.who())})
			}
			continue
		}
		base := fmt.Sprintf("listens on all interfaces (%s)%s", where, s.who())
		if firewallOff {
			sev := findings.SevWarn
			if exp {
				sev = findings.SevInfo
			}
			if sens {
				sev = findings.SevFail
			}
			c.Add(findings.Finding{Rule: "net.public-listener", Severity: sev, Path: "listen:" + s.name(),
				Message: base + " and no host firewall filters it",
				Fix:     "bind to 127.0.0.1 (or the one interface that needs it), or enable ufw with default deny"})
			continue
		}
		if !known {
			sev := findings.SevWarn
			if exp {
				sev = findings.SevInfo
			}
			c.Add(findings.Finding{Rule: "net.public-listener", Severity: sev, Path: "listen:" + s.name(),
				Message: base + "; ufw rules could not be read, so reachability is unknown",
				Fix:     "bind to 127.0.0.1 if only local clients use it; re-run with --ufw-status (output of `sudo ufw status verbose`) to reconcile"})
			continue
		}
		allow, any := matchingAllow(u.Rules, s.proto, s.port)
		switch {
		case allow == nil:
			sev := findings.SevWarn
			if exp {
				sev = findings.SevInfo
			}
			c.Add(findings.Finding{Rule: "net.unneeded-bind", Severity: sev, Path: "listen:" + s.name(),
				Message: base + " but no ufw rule allows it, so only local clients can use it",
				Fix:     "bind it to 127.0.0.1 so a firewall change (or Docker's own iptables rules) cannot expose it; or add an explicit `ufw allow from <subnet> to any port " + fmt.Sprint(s.port) + "`"})
		case any:
			sev := findings.SevWarn
			switch {
			case sens:
				sev = findings.SevFail
			case exp:
				sev = findings.SevInfo
			}
			c.Add(findings.Finding{Rule: "net.exposed", Severity: sev, Path: "listen:" + s.name(),
				Message: base + " and ufw allows it from anywhere (" + allow.Raw + ")",
				Fix:     "restrict the rule to the LAN (`ufw allow from 192.168.0.0/24 to any port " + fmt.Sprint(s.port) + "`), or add it to host.net.expected_public"})
		default:
			sev := findings.SevInfo
			if sens {
				sev = findings.SevWarn
			}
			c.Add(findings.Finding{Rule: "net.exposed", Severity: sev, Path: "listen:" + s.name(),
				Message: base + "; ufw allows it from " + allow.From + " (" + allow.Raw + ")"})
		}
	}

	// Allow rules without a listener.
	if known && u.Enabled {
		for _, r := range u.Rules {
			if !r.allows() || len(r.Ports) == 0 {
				continue
			}
			used := false
			for _, l := range ns.Listeners {
				if l.Scope != "loopback" && r.matches(l.Proto, l.Port) {
					used = true
					break
				}
			}
			if !used {
				c.Add(findings.Finding{Rule: "net.allow-unused", Severity: findings.SevInfo, Path: "ufw:" + r.Raw,
					Message: "ufw allows this, but nothing listens on it",
					Fix:     "delete the rule if the service is gone (`sudo ufw status numbered`, `sudo ufw delete N`)"})
			}
		}
	}
}

// matchingAllow returns the broadest allow rule for proto/port (from
// anywhere preferred) and whether it is from anywhere.
func matchingAllow(rules []UfwRule, proto string, port int) (*UfwRule, bool) {
	var best *UfwRule
	for i := range rules {
		r := &rules[i]
		if !r.allows() || !r.matches(proto, port) {
			continue
		}
		if r.fromAnywhere() {
			return r, true
		}
		if best == nil {
			best = r
		}
	}
	return best, false
}
