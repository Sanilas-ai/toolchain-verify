package hostsec

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Ufw is the firewall state as far as it could be read.
type Ufw struct {
	// Source: "rules" (/etc/ufw/user*.rules), "status" (ufw status
	// output) or "" when the rules could not be read.
	Source string `json:"source,omitempty"`
	// Enabled: from ufw.conf (ENABLED=yes) or "Status: active".
	Enabled bool `json:"enabled"`
	// DefaultIncoming: "deny", "reject", "allow" or "" (unknown).
	DefaultIncoming string    `json:"default_incoming,omitempty"`
	Rules           []UfwRule `json:"rules,omitempty"`
	Note            string    `json:"note,omitempty"`
}

// UfwRule is one incoming rule.
type UfwRule struct {
	Action string     `json:"action"` // allow, limit, deny, reject
	Proto  string     `json:"proto,omitempty"`
	Ports  []PortSpec `json:"ports,omitempty"` // empty = any port
	From   string     `json:"from"`            // "any" or a CIDR/address
	To     string     `json:"to,omitempty"`    // destination address ("any")
	Iface  string     `json:"iface,omitempty"`
	V6     bool       `json:"v6,omitempty"`
	Raw    string     `json:"raw"`
}

func (r UfwRule) allows() bool { return r.Action == "allow" || r.Action == "limit" }

func (r UfwRule) fromAnywhere() bool {
	switch r.From {
	case "", "any", "0.0.0.0/0", "::/0", "Anywhere":
		return true
	}
	return false
}

// matches reports whether the rule covers proto/port.
func (r UfwRule) matches(proto string, port int) bool {
	if r.Proto != "" && r.Proto != "any" && r.Proto != proto {
		return false
	}
	if len(r.Ports) == 0 {
		return true
	}
	for _, p := range r.Ports {
		if port >= p.Lo && port <= p.Hi && (p.Proto == "" || p.Proto == proto) {
			return true
		}
	}
	return false
}

// readUfw gathers the ufw state: ufw.conf and /etc/default/ufw are
// world-readable; user.rules is normally root-only, in which case the
// output of `ufw status verbose` can be supplied instead.
func readUfw(e *env, status []byte) *Ufw {
	u := &Ufw{}
	installed := false
	if data, err := e.read("/etc/ufw/ufw.conf"); err == nil {
		installed = true
		u.Enabled = confValue(string(data), "ENABLED") == "yes"
	}
	if data, err := e.read("/etc/default/ufw"); err == nil {
		installed = true
		switch strings.ToUpper(confValue(string(data), "DEFAULT_INPUT_POLICY")) {
		case "DROP":
			u.DefaultIncoming = "deny"
		case "REJECT":
			u.DefaultIncoming = "reject"
		case "ACCEPT":
			u.DefaultIncoming = "allow"
		}
	}
	apps := ufwApps(e)
	if len(status) > 0 {
		installed = true
		if err := parseUfwStatus(string(status), apps, u); err != nil {
			u.Note = err.Error()
		}
		return u
	}
	if !installed {
		return nil
	}
	v4, err4 := e.read("/etc/ufw/user.rules")
	v6, err6 := e.read("/etc/ufw/user6.rules")
	if err4 != nil && err6 != nil {
		u.Note = "/etc/ufw/user.rules is not readable (root only); pass the output of `sudo ufw status verbose` with --ufw-status FILE"
		return u
	}
	u.Source = "rules"
	u.Rules = append(parseUserRules(string(v4), false), parseUserRules(string(v6), true)...)
	return u
}

func confValue(text, key string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == key {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}

// ufwApps reads application profiles: name -> port specs
// ("ports=137,138/udp|139,445/tcp").
func ufwApps(e *env) map[string][]PortSpec {
	out := map[string][]PortSpec{}
	for _, p := range e.glob("/etc/ufw/applications.d/*") {
		data, err := e.read(p)
		if err != nil {
			continue
		}
		name := ""
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
				name = line[1 : len(line)-1]
				continue
			}
			if v, ok := strings.CutPrefix(line, "ports="); ok && name != "" {
				out[name] = parseAppPorts(v)
			}
		}
	}
	return out
}

func parseAppPorts(v string) []PortSpec {
	var out []PortSpec
	for _, grp := range strings.Split(v, "|") {
		body, proto, _ := strings.Cut(grp, "/")
		out = append(out, parsePortList(body, proto)...)
	}
	return out
}

// parsePortList parses "22", "80,443", "8000:8010" with a protocol.
func parsePortList(body, proto string) []PortSpec {
	if proto == "any" {
		proto = ""
	}
	var out []PortSpec
	for _, p := range strings.Split(body, ",") {
		lo, hi, rng := strings.Cut(strings.TrimSpace(p), ":")
		a, err := strconv.Atoi(lo)
		if err != nil {
			continue
		}
		b := a
		if rng {
			if b, err = strconv.Atoi(hi); err != nil {
				continue
			}
		}
		out = append(out, PortSpec{Lo: a, Hi: b, Proto: proto})
	}
	return out
}

// parseUserRules reads "### tuple ### ACTION PROTO DPORT DST SPORT SRC
// [DAPP SAPP] DIRECTION" comment lines that ufw keeps in user.rules.
func parseUserRules(text string, v6 bool) []UfwRule {
	var out []UfwRule
	for _, line := range strings.Split(text, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "### tuple ###")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) != 7 && len(f) != 9 {
			continue
		}
		dir := f[len(f)-1]
		dirBase, iface, _ := strings.Cut(dir, "_")
		if dirBase != "in" {
			continue
		}
		action, _, _ := strings.Cut(f[0], "_") // allow_log -> allow
		r := UfwRule{Action: action, Proto: f[1], To: f[3], From: f[5], Iface: iface, V6: v6, Raw: strings.TrimSpace(rest)}
		if f[2] != "any" {
			r.Ports = parsePortList(f[2], r.Proto)
		}
		out = append(out, r)
	}
	return out
}

var (
	colSplit    = regexp.MustCompile(`\s{2,}`)
	defaultInRe = regexp.MustCompile(`Default:\s*(\w+)\s*\(incoming\)`)
	toPortRe    = regexp.MustCompile(`^(?:(\S+)\s+)?(\d[\d,:]*)(?:/(tcp|udp))?$`)
	onIfaceRe   = regexp.MustCompile(`\s+on\s+(\S+)$`)
)

// parseUfwStatus parses `ufw status [verbose|numbered]` output.
func parseUfwStatus(text string, apps map[string][]PortSpec, u *Ufw) error {
	u.Source = "status"
	sawStatus := false
	inTable := false
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, " \r")
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "Status:"):
			sawStatus = true
			u.Enabled = strings.TrimSpace(strings.TrimPrefix(t, "Status:")) == "active"
			continue
		case strings.HasPrefix(t, "Default:"):
			if m := defaultInRe.FindStringSubmatch(t); m != nil {
				u.DefaultIncoming = strings.ToLower(m[1])
			}
			continue
		case strings.HasPrefix(t, "--"):
			inTable = true
			continue
		case t == "" || strings.HasPrefix(t, "To ") || !inTable:
			continue
		}
		if i := strings.Index(t, " # "); i >= 0 {
			t = strings.TrimSpace(t[:i]) // rule comment
		}
		if strings.HasPrefix(t, "[") { // numbered: "[ 1] 22/tcp ..."
			if j := strings.IndexByte(t, ']'); j > 0 {
				t = strings.TrimSpace(t[j+1:])
			}
		}
		cols := colSplit.Split(t, -1)
		if len(cols) < 3 {
			return fmt.Errorf("cannot parse ufw status line %q", t)
		}
		to, action, from := cols[0], strings.Fields(strings.ToLower(cols[1])), cols[2]
		if len(action) == 0 {
			continue
		}
		if len(action) > 1 && action[1] != "in" {
			continue // OUT / FWD rules
		}
		r := UfwRule{Action: action[0], Raw: strings.Join(strings.Fields(t), " ")}
		if strings.HasSuffix(to, "(v6)") {
			r.V6 = true
			to = strings.TrimSpace(strings.TrimSuffix(to, "(v6)"))
		}
		if m := onIfaceRe.FindStringSubmatch(to); m != nil {
			r.Iface = m[1]
			to = strings.TrimSpace(to[:len(to)-len(m[0])])
		}
		from = strings.TrimSpace(strings.TrimSuffix(from, "(v6)"))
		if strings.HasPrefix(from, "Anywhere") {
			r.From = "any"
		} else {
			r.From = strings.Fields(from)[0]
		}
		switch {
		case to == "Anywhere":
			r.To = "any"
		case toPortRe.MatchString(to):
			m := toPortRe.FindStringSubmatch(to)
			r.To = m[1]
			if r.To == "" {
				r.To = "any"
			}
			r.Proto = m[3]
			r.Ports = parsePortList(m[2], m[3])
		default:
			name, dst := to, "any"
			if f := strings.Fields(to); len(f) == 2 && !isAppName(apps, to) {
				dst, name = f[0], f[1]
			}
			ports, ok := apps[name]
			if !ok {
				r.To = dst
				// A destination address without port: all ports.
				if f := strings.Fields(to); len(f) == 1 && looksLikeAddr(f[0]) {
					r.To = f[0]
					break
				}
				return fmt.Errorf("unknown ufw application profile %q (not in /etc/ufw/applications.d)", name)
			}
			r.To, r.Ports = dst, ports
		}
		u.Rules = append(u.Rules, r)
	}
	if !sawStatus {
		return fmt.Errorf("no \"Status:\" line in the ufw status output")
	}
	return nil
}

func isAppName(apps map[string][]PortSpec, s string) bool { _, ok := apps[s]; return ok }

func looksLikeAddr(s string) bool {
	return strings.ContainsAny(s, ".:") && strings.Trim(s, "0123456789abcdefABCDEF.:/") == ""
}
