// Package check verifies installed tools against a manifest.
package check

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Sanilas-ai/toolchain-verify/internal/manifest"
	"github.com/Sanilas-ai/toolchain-verify/internal/version"
)

// Status values for a tool result.
const (
	StatusOK   = "ok"
	StatusFail = "fail"
	StatusSkip = "skip"
)

// Options control how tools are located and probed.
type Options struct {
	// Root, if set, replaces PATH: tools are looked up in Root/bin then Root,
	// and relative path patterns are resolved against Root.
	Root string
	// PathEnv is the search path when Root is empty (default: $PATH).
	PathEnv string
	// Timeout per version probe (default 10s).
	Timeout time.Duration
	// InContainer overrides container detection (nil = autodetect).
	InContainer *bool
}

// Result is the outcome for one tool.
type Result struct {
	Name       string   `json:"name"`
	Status     string   `json:"status"`
	Constraint string   `json:"constraint,omitempty"`
	Found      string   `json:"found,omitempty"`
	Resolved   string   `json:"resolved,omitempty"`
	Version    string   `json:"version,omitempty"`
	SHA256     string   `json:"sha256,omitempty"`
	Problems   []string `json:"problems,omitempty"`
}

// Report is the outcome for a whole manifest.
type Report struct {
	Manifest    string   `json:"manifest"`
	InContainer bool     `json:"in_container"`
	OK          bool     `json:"ok"`
	Problems    []string `json:"problems,omitempty"`
	Tools       []Result `json:"tools"`
}

// Counts returns the number of ok, failed and skipped tools.
func (r *Report) Counts() (ok, fail, skip int) {
	for _, t := range r.Tools {
		switch t.Status {
		case StatusOK:
			ok++
		case StatusFail:
			fail++
		case StatusSkip:
			skip++
		}
	}
	return
}

// Run checks every tool in m.
func Run(m *manifest.Manifest, manifestPath string, opt Options) *Report {
	if opt.Timeout == 0 {
		opt.Timeout = 10 * time.Second
	}
	rep := &Report{Manifest: manifestPath, OK: true}
	if opt.InContainer != nil {
		rep.InContainer = *opt.InContainer
	} else {
		rep.InContainer = DetectContainer()
	}
	if m.RequireContainer != nil && *m.RequireContainer != rep.InContainer {
		want := "inside a container (sandbox)"
		if !*m.RequireContainer {
			want = "on the host (not in a container)"
		}
		rep.Problems = append(rep.Problems, "manifest requires running "+want)
		rep.OK = false
	}
	for i := range m.Tools {
		r := checkTool(&m.Tools[i], m.Dir, opt)
		if r.Status == StatusFail {
			rep.OK = false
		}
		rep.Tools = append(rep.Tools, r)
	}
	return rep
}

func checkTool(t *manifest.Tool, manifestDir string, opt Options) Result {
	r := Result{Name: t.Name, Constraint: t.Constraint.String()}
	fail := func(format string, a ...any) {
		r.Status = StatusFail
		r.Problems = append(r.Problems, fmt.Sprintf(format, a...))
	}

	found, err := locate(t.Command, opt)
	if err != nil {
		if t.Optional {
			r.Status = StatusSkip
			r.Problems = append(r.Problems, err.Error()+" (optional)")
			return r
		}
		fail("%v", err)
		return r
	}
	r.Found = found
	resolved, err := filepath.EvalSymlinks(found)
	if err != nil {
		fail("resolve symlinks: %v", err)
		return r
	}
	if resolved, err = filepath.Abs(resolved); err == nil {
		r.Resolved = resolved
	}

	if t.Path != "" {
		pat := t.Path
		if !filepath.IsAbs(pat) {
			base := manifestDir
			if opt.Root != "" {
				base = opt.Root
			}
			pat = filepath.Join(base, pat)
		}
		re, err := globToRegexp(filepath.ToSlash(pat))
		if err != nil {
			fail("bad path pattern %q: %v", t.Path, err)
		} else if !re.MatchString(filepath.ToSlash(found)) && !re.MatchString(filepath.ToSlash(r.Resolved)) {
			fail("path %s (resolved %s) does not match %q", found, r.Resolved, pat)
		}
	}

	sum, err := fileSHA256(r.Resolved)
	if err != nil {
		fail("hash: %v", err)
	} else {
		r.SHA256 = sum
		if t.SHA256 != "" && sum != t.SHA256 {
			fail("sha256 mismatch: got %s, want %s", sum, t.SHA256)
		}
	}

	out, probeErr := probe(found, t.VersionArgs, opt.Timeout)
	v, err := extractVersion(out, t)
	if err != nil {
		if probeErr != nil {
			fail("version probe `%s %s` failed: %v", t.Command, strings.Join(t.VersionArgs, " "), probeErr)
		} else {
			fail("%v", err)
		}
	} else {
		r.Version = v.String()
		if !t.Constraint.Check(v) {
			fail("version %s does not satisfy %q", v, t.Constraint.String())
		}
	}
	if r.Status == "" {
		r.Status = StatusOK
	}
	return r
}

func extractVersion(out string, t *manifest.Tool) (version.Version, error) {
	if t.Regex == nil {
		return version.Extract(out)
	}
	m := t.Regex.FindStringSubmatch(out)
	if m == nil {
		return version.Version{}, fmt.Errorf("version_regex %q did not match output %q", t.VersionRegex, strings.TrimSpace(out))
	}
	s := m[0]
	if i := t.Regex.SubexpIndex("version"); i > 0 {
		s = m[i]
	} else if len(m) > 1 {
		s = m[1]
	}
	if v, err := version.Parse(s); err == nil {
		return v, nil
	}
	return version.Extract(s)
}

// locate finds an executable for cmd.
func locate(cmd string, opt Options) (string, error) {
	if strings.ContainsRune(cmd, '/') || strings.ContainsRune(cmd, filepath.Separator) {
		p := cmd
		if !filepath.IsAbs(p) && opt.Root != "" {
			p = filepath.Join(opt.Root, p)
		}
		if isExecutable(p) {
			return filepath.Abs(p)
		}
		return "", fmt.Errorf("%s: not found or not executable", p)
	}
	var dirs []string
	if opt.Root != "" {
		dirs = []string{filepath.Join(opt.Root, "bin"), opt.Root}
	} else {
		pathEnv := opt.PathEnv
		if pathEnv == "" {
			pathEnv = os.Getenv("PATH")
		}
		dirs = filepath.SplitList(pathEnv)
	}
	for _, d := range dirs {
		if d == "" || !filepath.IsAbs(d) {
			// Empty or relative PATH entries resolve against the CWD, a
			// classic way to pick up a planted binary; never use them.
			continue
		}
		p := filepath.Join(d, cmd)
		if isExecutable(p) {
			return p, nil
		}
	}
	where := "PATH"
	if opt.Root != "" {
		where = opt.Root
	}
	return "", fmt.Errorf("%s: not found in %s", cmd, where)
}

func isExecutable(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func probe(bin string, args []string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := exec.CommandContext(ctx, bin, args...)
	var buf bytes.Buffer
	c.Stdout, c.Stderr = &buf, &buf // some tools (java, older python) print to stderr
	c.Stdin = nil
	err := c.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		err = fmt.Errorf("timed out after %s", timeout)
	}
	return buf.String(), err
}

// DetectContainer reports whether the process appears to run in a container.
//
// Heuristic (env alone is never enough — $container is trivially spoofable and
// must not silence policy.require-container on the host):
//  1. Marker files: /.dockerenv (Docker) or /run/.containerenv (Podman), or
//     /run/systemd/container (systemd-nspawn).
//  2. Else /proc/1/cgroup names docker|containerd|kubepods|libpod|lxc|podman.
//  3. Else /proc/self/mountinfo shows overlay/overlay2 mounted on "/" (common
//     on cgroup v2 where the cgroup file is just "0::/").
//
// Detection is still a heuristic, not a security boundary: a privileged process
// can plant marker files. Downgrading policy.require-container to INFO only
// happens when this heuristic says we are already in a container; spoofing
// $container=docker on the host no longer skips the WARN.
func DetectContainer() bool {
	return detectContainer(os.Stat, os.ReadFile)
}

func detectContainer(stat func(string) (os.FileInfo, error), readFile func(string) ([]byte, error)) bool {
	for _, f := range []string{"/.dockerenv", "/run/.containerenv", "/run/systemd/container"} {
		if _, err := stat(f); err == nil {
			return true
		}
	}
	if b, err := readFile("/proc/1/cgroup"); err == nil {
		s := string(b)
		for _, k := range []string{"docker", "containerd", "kubepods", "libpod", "lxc", "podman"} {
			if strings.Contains(s, k) {
				return true
			}
		}
	}
	if b, err := readFile("/proc/self/mountinfo"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			// mountinfo: ID parent major:minor root mountpoint opts [opt]* - fstype ...
			dash := strings.Index(line, " - ")
			if dash < 0 {
				continue
			}
			left := strings.Fields(line[:dash])
			right := strings.Fields(line[dash+3:])
			if len(left) < 5 || len(right) < 1 {
				continue
			}
			mountPoint, fsType := left[4], right[0]
			if mountPoint == "/" && (fsType == "overlay" || fsType == "overlay2") {
				return true
			}
		}
	}
	return false
}
