package hostsec

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Listener is a listening TCP socket or a bound UDP socket.
type Listener struct {
	Proto   string `json:"proto"` // tcp or udp
	Addr    string `json:"addr"`  // 0.0.0.0, ::, 127.0.0.1, 192.168.0.5, ...
	Port    int    `json:"port"`
	V6      bool   `json:"v6,omitempty"`
	Scope   string `json:"scope"` // all, loopback, address
	Process string `json:"process,omitempty"`
	PID     int    `json:"pid,omitempty"`
	UID     int    `json:"uid"`
	inode   string
}

// Endpoint is "addr:port/proto".
func (l Listener) Endpoint() string {
	a := l.Addr
	if strings.Contains(a, ":") {
		a = "[" + a + "]"
	}
	return fmt.Sprintf("%s:%d/%s", a, l.Port, l.Proto)
}

func scopeOf(ip net.IP) string {
	switch {
	case ip == nil:
		return "all"
	case ip.IsUnspecified():
		return "all"
	case ip.IsLoopback():
		return "loopback"
	}
	return "address"
}

// procListeners parses /proc/net/{tcp,tcp6,udp,udp6}.
func procListeners(e *env) ([]Listener, error) {
	var out []Listener
	read := 0
	for _, f := range []struct {
		file, proto string
		v6          bool
	}{{"tcp", "tcp", false}, {"tcp6", "tcp", true}, {"udp", "udp", false}, {"udp6", "udp", true}} {
		data, err := e.read("/proc/net/" + f.file)
		if err != nil {
			continue
		}
		read++
		ls, err := parseProcNet(string(data), f.proto, f.v6)
		if err != nil {
			return nil, fmt.Errorf("/proc/net/%s: %w", f.file, err)
		}
		out = append(out, ls...)
	}
	if read == 0 {
		return nil, fmt.Errorf("/proc/net/tcp is not readable")
	}
	return out, nil
}

// parseProcNet parses one /proc/net table. TCP sockets in state 0A
// (LISTEN) and UDP sockets in state 07 with no remote peer are returned.
func parseProcNet(data, proto string, v6 bool) ([]Listener, error) {
	var out []Listener
	for i, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 10 {
			continue
		}
		st := f[3]
		if (proto == "tcp" && st != "0A") || (proto == "udp" && st != "07") {
			continue
		}
		ip, port, err := parseHexAddr(f[1])
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		if proto == "udp" {
			rip, rport, err := parseHexAddr(f[2])
			if err != nil || !rip.IsUnspecified() || rport != 0 {
				continue // connected UDP socket
			}
		}
		uid, _ := strconv.Atoi(f[7])
		out = append(out, Listener{Proto: proto, Addr: ip.String(), Port: port, V6: v6, Scope: scopeOf(ip), UID: uid, inode: f[9]})
	}
	return out, nil
}

// parseHexAddr decodes "0100007F:0016" (IPv4) or a 32-digit IPv6 address;
// each 32-bit word is in host (little-endian) byte order.
func parseHexAddr(s string) (net.IP, int, error) {
	a, p, ok := strings.Cut(s, ":")
	if !ok {
		return nil, 0, fmt.Errorf("bad address %q", s)
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return nil, 0, fmt.Errorf("bad port in %q", s)
	}
	b, err := hex.DecodeString(a)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return nil, 0, fmt.Errorf("bad address %q", s)
	}
	ip := make(net.IP, len(b))
	for w := 0; w < len(b); w += 4 {
		ip[w], ip[w+1], ip[w+2], ip[w+3] = b[w+3], b[w+2], b[w+1], b[w]
	}
	if v4 := ip.To4(); v4 != nil && len(b) == 16 && !ip.IsUnspecified() {
		ip = v4 // ::ffff:a.b.c.d
	}
	return ip, int(port), nil
}

// attachProcesses maps socket inodes to the processes that the current
// user may inspect (other users' /proc/<pid>/fd are unreadable).
func attachProcesses(e *env, ls []Listener) {
	want := map[string][]int{}
	for i, l := range ls {
		if l.inode != "" && l.inode != "0" {
			want["socket:["+l.inode+"]"] = append(want["socket:["+l.inode+"]"], i)
		}
	}
	if len(want) == 0 {
		return
	}
	dirs, _ := os.ReadDir(e.path("/proc"))
	scanned := 0
	for _, d := range dirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil || scanned > 4000 {
			continue
		}
		scanned++
		fdDir := e.path(filepath.Join("/proc", d.Name(), "fd"))
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		var comm string
		for _, fd := range fds {
			t, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			idx, ok := want[t]
			if !ok {
				continue
			}
			if comm == "" {
				c, _ := os.ReadFile(e.path(filepath.Join("/proc", d.Name(), "comm")))
				comm = strings.TrimSpace(string(c))
				if comm == "" {
					comm = "?"
				}
			}
			for _, i := range idx {
				ls[i].Process, ls[i].PID = comm, pid
			}
		}
	}
}

// ParseSS parses `ss -tuln[p][H]` output.
func ParseSS(data string) ([]Listener, error) {
	var out []Listener
	other := 0
	for n, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] == "Netid" || f[0] == "State" {
			continue
		}
		other++
		if len(f) < 4 {
			continue
		}
		proto := ""
		switch f[0] {
		case "tcp", "udp":
			proto, f = f[0], f[1:]
		case "LISTEN":
			proto = "tcp"
		case "UNCONN":
			proto = "udp"
		default:
			continue // raw, unix, sctp, ...
		}
		if len(f) < 4 || (f[0] != "LISTEN" && f[0] != "UNCONN") {
			continue
		}
		local := f[3]
		i := strings.LastIndexByte(local, ':')
		if i < 0 {
			return nil, fmt.Errorf("line %d: bad local address %q", n+1, local)
		}
		host, portS := local[:i], local[i+1:]
		port, err := strconv.Atoi(portS)
		if err != nil {
			if portS == "*" {
				continue
			}
			return nil, fmt.Errorf("line %d: bad port %q", n+1, portS)
		}
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		if j := strings.IndexByte(host, '%'); j >= 0 {
			host = host[:j] // 127.0.0.53%lo, [fe80::1%eth0]
		}
		l := Listener{Proto: proto, Port: port}
		if host == "*" {
			l.Addr, l.Scope, l.V6 = "*", "all", true
		} else {
			ip := net.ParseIP(host)
			if ip == nil {
				return nil, fmt.Errorf("line %d: bad address %q", n+1, host)
			}
			l.V6 = ip.To4() == nil || strings.Contains(host, ":")
			if v4 := ip.To4(); v4 != nil {
				ip = v4
			}
			l.Addr, l.Scope = ip.String(), scopeOf(ip)
		}
		if k := strings.Index(line, `users:(("`); k >= 0 {
			rest := line[k+9:]
			if e := strings.IndexByte(rest, '"'); e > 0 {
				l.Process = rest[:e]
			}
			if p := strings.Index(rest, "pid="); p >= 0 {
				num := rest[p+4:]
				if e := strings.IndexAny(num, ",)"); e > 0 {
					l.PID, _ = strconv.Atoi(num[:e])
				}
			}
		}
		out = append(out, l)
	}
	if len(out) == 0 && other > 0 {
		return nil, fmt.Errorf("no LISTEN/UNCONN sockets in the ss output (expected `ss -tuln`)")
	}
	return out, nil
}

// dedupe merges duplicate (proto, addr, port) entries and sorts.
func dedupe(ls []Listener) []Listener {
	seen := map[string]int{}
	var out []Listener
	for _, l := range ls {
		k := l.Endpoint()
		if i, ok := seen[k]; ok {
			if out[i].Process == "" {
				out[i].Process, out[i].PID = l.Process, l.PID
			}
			continue
		}
		seen[k] = len(out)
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Proto != b.Proto {
			return a.Proto > b.Proto // tcp first
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Addr < b.Addr
	})
	return out
}

// ephemeralRange reads net.ipv4.ip_local_port_range (default 32768-60999).
func ephemeralRange(e *env) (int, int) {
	lo, hi := 32768, 60999
	if data, err := e.read("/proc/sys/net/ipv4/ip_local_port_range"); err == nil {
		f := strings.Fields(string(data))
		if len(f) == 2 {
			if a, err := strconv.Atoi(f[0]); err == nil {
				if b, err := strconv.Atoi(f[1]); err == nil && a <= b {
					lo, hi = a, b
				}
			}
		}
	}
	return lo, hi
}
