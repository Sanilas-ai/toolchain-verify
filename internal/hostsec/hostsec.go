package hostsec

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

// Options control a run. Zero values select the live host.
type Options struct {
	// Root is prepended to every absolute path read (tests use a fake
	// tree; default "/").
	Root string
	// Apt and Net select the check groups (both when no group is set).
	// Vps selects the internet-facing server profile (opt-in).
	Apt, Net, Vps bool
	// SshdT is the output of `sudo sshd -T` (optional; sshd_config and its
	// Include drop-ins are evaluated otherwise).
	SshdT []byte
	// Timedatectl is the output of `timedatectl show` (optional).
	Timedatectl []byte
	// GitVersion is the output of `git --version` (optional; the dpkg git
	// package version is used otherwise).
	GitVersion []byte
	// Nft is the output of `sudo nft list ruleset` (optional).
	Nft []byte
	// UfwStatus is the output of `ufw status [verbose]` (for hosts where
	// /etc/ufw/user.rules is readable by root only).
	UfwStatus []byte
	// SS is the output of `ss -tulnH` (optional; /proc/net is used
	// otherwise).
	SS     []byte
	Strict bool
	Now    func() time.Time
	// Groups returns the current user's group names.
	Groups func() ([]string, error)
}

// Report is the result of a run.
type Report struct {
	OS       string             `json:"os,omitempty"`
	Codename string             `json:"codename,omitempty"`
	Kernel   *Kernel            `json:"kernel,omitempty"`
	Apt      *AptState          `json:"apt,omitempty"`
	Net      *NetState          `json:"net,omitempty"`
	Vps      *VpsState          `json:"vps,omitempty"`
	OK       bool               `json:"ok"`
	Strict   bool               `json:"strict"`
	Findings []findings.Finding `json:"findings"`
	Ignored  int                `json:"ignored,omitempty"`
}

// env reads files below a root.
type env struct {
	root string
	now  time.Time
}

func (e *env) path(p string) string {
	if e.root == "" || e.root == "/" {
		return p
	}
	return filepath.Join(e.root, p)
}

const maxSmallFile = 1 << 20

func (e *env) read(p string) ([]byte, error) {
	f, err := os.Open(e.path(p))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxSmallFile))
}

func (e *env) stat(p string) (os.FileInfo, error) { return os.Stat(e.path(p)) }

func (e *env) exists(p string) bool { _, err := e.stat(p); return err == nil }

func (e *env) glob(pattern string) []string {
	m, _ := filepath.Glob(e.path(pattern))
	out := make([]string, 0, len(m))
	for _, p := range m {
		if e.root != "" && e.root != "/" {
			rel, err := filepath.Rel(e.root, p)
			if err != nil {
				continue
			}
			p = "/" + rel
		}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Run performs the selected checks.
func Run(p *Policy, opt Options) (*Report, error) {
	if p == nil {
		p = &Policy{}
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if !opt.Apt && !opt.Net && !opt.Vps {
		opt.Apt, opt.Net = true, true
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Groups == nil {
		opt.Groups = currentGroups
	}
	e := &env{root: opt.Root, now: opt.Now()}
	c := &findings.Collector{Ignore: p.Ignore}
	rep := &Report{Strict: opt.Strict || p.Strict}
	rep.OS, rep.Codename = osRelease(e)
	dpkg := readDpkgStatus(e)
	if opt.Apt {
		checkApt(e, p.aptPolicy(), rep, dpkg, c)
		checkKernel(e, p.KernelFloors, rep, dpkg, c)
		checkSnaps(e, p.aptPolicy(), opt.Groups, c)
	}
	if opt.Net {
		checkNet(e, p.Net, opt, rep, c)
	}
	if opt.Vps {
		checkVps(e, opt, rep, dpkg, c)
	}
	rep.Findings = c.Sorted()
	rep.Ignored = c.Ignored
	rep.OK = findings.OK(rep.Findings, rep.Strict)
	return rep, nil
}

func currentGroups() ([]string, error) {
	u, err := user.Current()
	if err != nil {
		return nil, err
	}
	ids, err := u.GroupIds()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, id := range ids {
		if g, err := user.LookupGroupId(id); err == nil {
			names = append(names, g.Name)
		}
	}
	return names, nil
}

func osRelease(e *env) (pretty, codename string) {
	data, err := e.read("/etc/os-release")
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch k {
		case "PRETTY_NAME":
			pretty = v
		case "VERSION_CODENAME":
			codename = v
		case "UBUNTU_CODENAME":
			if codename == "" {
				codename = v
			}
		}
	}
	return pretty, codename
}

// stanzas calls fn for every RFC 822-style stanza in r with the fields
// listed in want (other fields, including multi-line ones, are skipped).
func stanzas(r io.Reader, want []string, fn func(map[string]string)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	cur := map[string]string{}
	flush := func() {
		if len(cur) > 0 {
			fn(cur)
			cur = map[string]string{}
		}
	}
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		i := bytes.IndexByte(line, ':')
		if i <= 0 {
			continue
		}
		k := line[:i]
		for _, w := range want {
			if string(k) == w {
				cur[w] = strings.TrimSpace(string(line[i+1:]))
				break
			}
		}
	}
	flush()
	return sc.Err()
}
