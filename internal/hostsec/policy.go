// Package hostsec implements read-only host security checks: apt/dpkg
// security-update lag, kernel CVE floors, unattended-upgrades health,
// reboot-required, risky snaps, and a reconciliation of listening sockets
// against ufw rules. It parses files under /var/lib/apt, /var/lib/dpkg,
// /etc and /proc; it never runs apt, dpkg, ufw or ss and changes nothing.
package hostsec

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Policy is the [host] manifest section.
type Policy struct {
	Apt *AptPolicy `toml:"apt"`
	Net *NetPolicy `toml:"net"`
	// KernelFloors are minimum running-kernel versions, typically one per
	// CVE that must be patched ([[host.kernel_floor]]).
	KernelFloors []KernelFloor `toml:"kernel_floor"`
	// Ignore suppresses findings: "rule" or "rule:path-glob".
	Ignore []string `toml:"ignore"`
	// Strict makes warnings fail the run.
	Strict bool `toml:"strict"`
}

// AptPolicy tunes the apt/dpkg checks ([host.apt]).
type AptPolicy struct {
	// SecurityFail is the number of pending security updates at which the
	// apt.security-pending finding fails (default 10; 1..N pending warn).
	SecurityFail int `toml:"security_pending_fail"`
	// ListsWarnHours: security package lists older than this warn
	// (default 48).
	ListsWarnHours int `toml:"lists_max_age_hours"`
	// ListsFailDays: older than this fails (default 7).
	ListsFailDays int `toml:"lists_fail_age_days"`
	// UnattendedMaxDays: unattended-upgrades last run older than this warns
	// (default 3).
	UnattendedMaxDays int `toml:"unattended_max_age_days"`
	// RebootMaxDays: a pending reboot older than this fails (default 7).
	RebootMaxDays int `toml:"reboot_max_age_days"`
	// RequireUnattended: missing or disabled unattended-upgrades warns
	// (default true).
	RequireUnattended *bool `toml:"require_unattended"`
	// WarnSnaps are snaps whose presence is reported (default ["lxd"]).
	WarnSnaps []string `toml:"warn_snaps"`
}

// KernelFloor is one minimum kernel version.
type KernelFloor struct {
	Name string `toml:"name"` // e.g. "Fragnesia"
	CVE  string `toml:"cve"`  // e.g. "CVE-2026-46300"
	// Min is the first fixed version, compared with dpkg rules against the
	// running kernel's package version (Ubuntu: "5.15.0-181.191") or, when
	// that is unknown, its release ("5.15.0-181").
	Min string `toml:"min"`
	// Series limits the floor to kernels whose release starts with it
	// (default: the first two components of Min, e.g. "5.15").
	Series string `toml:"series"`
	// Severity of a running kernel below Min: "fail" (default) or "warn".
	Severity string   `toml:"severity"`
	Refs     []string `toml:"refs"`
}

// NetPolicy tunes the listener/ufw reconciliation ([host.net]).
type NetPolicy struct {
	// ExpectedPublic are listeners that may listen on all interfaces, as
	// port specs: "22/tcp", "445", "137-138/udp".
	ExpectedPublic []string `toml:"expected_public"`
	// Sensitive are ports that must never be reachable from the network
	// (default: Docker API, databases, Ollama, Jupyter, ...). A wildcard
	// listener on one fails when ufw does not block it.
	Sensitive []string `toml:"sensitive_ports"`
	// IncludeEphemeralUDP also reports UDP sockets bound to ports in the
	// kernel's ephemeral range (client sockets; skipped by default).
	IncludeEphemeralUDP bool `toml:"include_ephemeral_udp"`
}

// DefaultSensitive lists ports of services that are dangerous to expose.
var DefaultSensitive = []string{
	"2375-2376/tcp", // Docker Engine API
	"11434/tcp",     // Ollama
	"6379/tcp",      // Redis
	"27017/tcp",     // MongoDB
	"5432/tcp",      // PostgreSQL
	"3306/tcp",      // MySQL/MariaDB
	"9200/tcp",      // Elasticsearch/OpenSearch
	"8888/tcp",      // Jupyter
	"5900-5910/tcp", // VNC
	"10250/tcp",     // kubelet
}

// DefaultExpectedPublic are client-side or link-local services that
// normally listen on all interfaces.
var DefaultExpectedPublic = []string{"68/udp", "546/udp", "5353/udp"}

func (p *Policy) aptPolicy() AptPolicy {
	var a AptPolicy
	if p != nil && p.Apt != nil {
		a = *p.Apt
	}
	if a.SecurityFail == 0 {
		a.SecurityFail = 10
	}
	if a.ListsWarnHours == 0 {
		a.ListsWarnHours = 48
	}
	if a.ListsFailDays == 0 {
		a.ListsFailDays = 7
	}
	if a.UnattendedMaxDays == 0 {
		a.UnattendedMaxDays = 3
	}
	if a.RebootMaxDays == 0 {
		a.RebootMaxDays = 7
	}
	if a.RequireUnattended == nil {
		t := true
		a.RequireUnattended = &t
	}
	if a.WarnSnaps == nil {
		a.WarnSnaps = []string{"lxd"}
	}
	return a
}

var cveRe = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// Validate checks the section.
func (p *Policy) Validate() error {
	if p.Apt != nil {
		a := p.Apt
		for name, v := range map[string]int{
			"security_pending_fail":   a.SecurityFail,
			"lists_max_age_hours":     a.ListsWarnHours,
			"lists_fail_age_days":     a.ListsFailDays,
			"unattended_max_age_days": a.UnattendedMaxDays,
			"reboot_max_age_days":     a.RebootMaxDays,
		} {
			if v < 0 {
				return fmt.Errorf("host.apt.%s must not be negative", name)
			}
		}
	}
	for i, f := range p.KernelFloors {
		where := fmt.Sprintf("host.kernel_floor #%d", i+1)
		if f.Name == "" && f.CVE == "" {
			return fmt.Errorf("%s: name or cve is required", where)
		}
		if f.CVE != "" && !cveRe.MatchString(f.CVE) {
			return fmt.Errorf("%s: cve %q is not of the form CVE-YYYY-NNNN", where, f.CVE)
		}
		if f.Min == "" || !isDigit(f.Min[0]) {
			return fmt.Errorf("%s: min must be a version such as \"5.15.0-181.191\"", where)
		}
		if f.Severity != "" && f.Severity != "fail" && f.Severity != "warn" {
			return fmt.Errorf("%s: severity must be \"fail\" or \"warn\"", where)
		}
	}
	if p.Net != nil {
		for _, list := range [][]string{p.Net.ExpectedPublic, p.Net.Sensitive} {
			for _, s := range list {
				if _, err := ParsePortSpec(s); err != nil {
					return fmt.Errorf("host.net: %w", err)
				}
			}
		}
	}
	return nil
}

// series returns the floor's series ("5.15").
func (f KernelFloor) series() string {
	if f.Series != "" {
		return f.Series
	}
	parts := strings.SplitN(f.Min, ".", 3)
	if len(parts) >= 2 {
		return parts[0] + "." + strings.TrimFunc(parts[1], func(r rune) bool { return r < '0' || r > '9' })
	}
	return parts[0]
}

func (f KernelFloor) label() string {
	switch {
	case f.Name != "" && f.CVE != "":
		return f.Name + " (" + f.CVE + ")"
	case f.CVE != "":
		return f.CVE
	}
	return f.Name
}

// PortSpec is a port range with an optional protocol ("" = any).
type PortSpec struct {
	Lo, Hi int
	Proto  string
}

// ParsePortSpec parses "22", "22/tcp", "137-138/udp" or "8000:8010/tcp".
func ParsePortSpec(s string) (PortSpec, error) {
	var ps PortSpec
	body, proto, _ := strings.Cut(strings.TrimSpace(s), "/")
	switch proto {
	case "", "tcp", "udp":
		ps.Proto = proto
	default:
		return ps, fmt.Errorf("port %q: protocol must be tcp or udp", s)
	}
	lo, hi, rng := strings.Cut(body, "-")
	if !rng {
		lo, hi, rng = strings.Cut(body, ":")
	}
	var err error
	if ps.Lo, err = strconv.Atoi(lo); err != nil || ps.Lo < 1 || ps.Lo > 65535 {
		return ps, fmt.Errorf("port %q: invalid port", s)
	}
	ps.Hi = ps.Lo
	if rng {
		if ps.Hi, err = strconv.Atoi(hi); err != nil || ps.Hi < ps.Lo || ps.Hi > 65535 {
			return ps, fmt.Errorf("port %q: invalid range", s)
		}
	}
	return ps, nil
}

// Match reports whether proto/port falls into the spec.
func (ps PortSpec) Match(proto string, port int) bool {
	return port >= ps.Lo && port <= ps.Hi && (ps.Proto == "" || ps.Proto == proto)
}

func matchAny(specs []PortSpec, proto string, port int) bool {
	for _, s := range specs {
		if s.Match(proto, port) {
			return true
		}
	}
	return false
}

func mustSpecs(list []string) []PortSpec {
	var out []PortSpec
	for _, s := range list {
		if ps, err := ParsePortSpec(s); err == nil {
			out = append(out, ps)
		}
	}
	return out
}
