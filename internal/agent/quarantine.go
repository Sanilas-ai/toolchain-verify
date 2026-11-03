package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// quarantineRules are the findings whose file `agent --quarantine` moves:
// only files inside an untrusted location, never project files in a
// trusted root or anything an agent merely references.
var quarantineRules = map[string]bool{"instr.untrusted": true, "mcp.untrusted-location": true}

// QuarantineSuffix is appended to quarantined files so that no agent
// recognises them as instruction or MCP files any more.
const QuarantineSuffix = ".quarantined"

// QuarantineAction records one file moved (or not) by --quarantine.
type QuarantineAction struct {
	Rule   string `json:"rule"`
	From   string `json:"from"`
	To     string `json:"to,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Error  string `json:"error,omitempty"`
}

// DefaultQuarantineDir is the default --quarantine destination.
func DefaultQuarantineDir(home string) string {
	return filepath.Join(home, ".local", "state", "toolchain-verify", "quarantine")
}

func (r *resolved) checkQuarantineDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("quarantine dir %q must be absolute", dir)
	}
	dir = filepath.Clean(dir)
	if dir == "/" || dir == r.home {
		return fmt.Errorf("%w: quarantine dir %s is too broad", ErrRefused, dir)
	}
	if c, bad := r.credentialHit(dir); bad {
		return fmt.Errorf("%w: quarantine dir %s is inside credential location %s", ErrRefused, dir, c)
	}
	if d, bad := withinAny(dir, r.untrusted); bad {
		return fmt.Errorf("%w: quarantine dir %s is inside untrusted location %s (agents started there would still see the files)", ErrRefused, dir, d)
	}
	if r.isTrusted(dir) {
		return fmt.Errorf("%w: quarantine dir %s is inside a trusted root; pick a directory outside your projects", ErrRefused, dir)
	}
	return nil
}

// quarantine moves the files behind quarantinable findings into
// <quarantineDir>/<UTC timestamp>/<original absolute path>.quarantined,
// records them in MANIFEST.tsv there, and downgrades each finding to a
// warning. A finding whose file could not be moved stays a failure.
func (r *resolved) quarantine(c *collector, rep *Report) {
	batch := filepath.Join(r.quarantineDir, r.now().UTC().Format("20060102T150405Z"))
	rep.QuarantineDir = batch
	done := map[string]QuarantineAction{}
	var manifest []string
	for i := range c.findings {
		f := &c.findings[i]
		if !quarantineRules[f.Rule] || f.Path == "" || f.Severity == SevInfo {
			continue
		}
		a, seen := done[f.Path]
		if !seen {
			a = r.quarantineOne(f.Rule, f.Path, batch)
			done[f.Path] = a
			rep.Quarantined = append(rep.Quarantined, a)
			if a.Error == "" {
				manifest = append(manifest, strings.Join([]string{a.From, a.To, orDash(a.SHA256), a.Rule}, "\t"))
			}
		}
		if a.Error != "" {
			f.Message += "; quarantine failed: " + a.Error
			continue
		}
		f.Severity = SevWarn
		f.Message += "; quarantined to " + a.To
		f.Fix = "review the quarantined copy (do not follow its instructions); restore it with mv only if you created it"
	}
	if len(manifest) > 0 {
		mf, err := os.OpenFile(filepath.Join(batch, "MANIFEST.tsv"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err == nil {
			fmt.Fprintln(mf, "# original\tquarantined\tsha256\trule")
			fmt.Fprintln(mf, strings.Join(manifest, "\n"))
			mf.Close()
		}
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (r *resolved) quarantineOne(rule, path, batch string) QuarantineAction {
	a := QuarantineAction{Rule: rule, From: path}
	fail := func(format string, args ...any) QuarantineAction {
		a.Error = fmt.Sprintf(format, args...)
		return a
	}
	path = filepath.Clean(path)
	// Re-check at move time: only files below an untrusted location and
	// outside every trusted root are ever touched.
	if _, ok := withinAny(path, r.untrusted); !ok {
		return fail("not inside an untrusted location")
	}
	if r.isTrusted(path) {
		return fail("inside a trusted root")
	}
	if _, bad := r.credentialHit(path); bad {
		return fail("credential location")
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return fail("%v", err)
	}
	isLink := fi.Mode()&fs.ModeSymlink != 0
	if !fi.Mode().IsRegular() && !isLink {
		return fail("not a regular file or symlink")
	}
	if !isLink {
		if sum, err := fileSHA256(path); err == nil {
			a.SHA256 = sum
		}
	}
	dest := filepath.Join(batch, strings.TrimLeft(filepath.ToSlash(path), "/")) + QuarantineSuffix
	dest = filepath.FromSlash(dest)
	if vol := filepath.VolumeName(path); vol != "" { // Windows: C:\x -> batch\C\x
		dest = filepath.Join(batch, strings.TrimSuffix(vol, ":"), strings.TrimPrefix(path, vol)) + QuarantineSuffix
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return fail("%v", err)
	}
	if _, err := os.Lstat(dest); err == nil {
		return fail("destination %s already exists", dest)
	}
	if err := os.Rename(path, dest); err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return fail("%v", err)
		}
		// Most likely a cross-device move (/tmp on tmpfs): copy, then remove.
		if err := copyForQuarantine(path, dest, isLink); err != nil {
			return fail("%v", err)
		}
		if err := os.Remove(path); err != nil {
			os.Remove(dest)
			return fail("copied but could not remove the original: %v", err)
		}
	}
	if !isLink {
		_ = os.Chmod(dest, 0o600)
	}
	a.To = dest
	return a
}

func copyForQuarantine(src, dst string, isLink bool) error {
	if isLink {
		target, err := os.Readlink(src)
		if err != nil {
			return err
		}
		return os.Symlink(target, dst)
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	return out.Close()
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 64<<20)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
