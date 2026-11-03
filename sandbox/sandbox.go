// Package sandbox builds hardened `docker run` / `podman run` invocations
// for executing untrusted commands, such as code written by an LLM:
//
//	docker run --rm --network none --read-only --cap-drop ALL
//	  --security-opt no-new-privileges --user 65534:65534 --ipc none
//	  --pids-limit 128 --memory 512m --memory-swap 512m --cpus 1
//	  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m IMAGE CMD...
//
// The package only builds arguments and an *exec.Cmd; it never starts
// anything itself. `toolchain-verify exec-lint` recognises calls to
// sandbox.Command and sandbox.Args as isolated.
package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Mount is a bind mount; read-only unless Writable.
type Mount struct {
	Source   string // absolute host path
	Target   string // absolute container path
	Writable bool
}

// Config describes the sandbox. Zero values select the hardened defaults.
type Config struct {
	Image         string   // required; pin it by digest (name@sha256:...)
	RequireDigest bool     // reject images not pinned by digest
	Runtime       string   // "docker" (default) or "podman"
	User          string   // default "65534:65534" (nobody); root is rejected
	Memory        string   // default "512m"
	CPUs          string   // default "1"
	PidsLimit     int      // default 128
	TmpfsSize     string   // size of the /tmp tmpfs, default "64m"
	Workdir       string   // default "/tmp", or the first mount's target
	Mounts        []Mount  // never the Docker socket, "/" or system dirs
	Env           []string // explicit KEY=VALUE pairs; the host env is not passed
	Stdin         bool     // keep stdin open (-i) to stream code in
}

// Errors returned by Args.
var (
	ErrNoImage     = errors.New("sandbox: image is required")
	ErrUnsafe      = errors.New("sandbox: unsafe configuration")
	ErrNotPinned   = errors.New("sandbox: image is not pinned by digest")
	forbiddenMount = []string{"/", "/etc", "/root", "/boot", "/proc", "/sys", "/dev", "/var/lib/docker", "/run", "/var/run"}
)

// Args returns the runtime arguments (starting with "run") for argv.
func Args(c Config, argv ...string) ([]string, error) {
	if strings.TrimSpace(c.Image) == "" {
		return nil, ErrNoImage
	}
	if strings.HasPrefix(c.Image, "-") {
		return nil, fmt.Errorf("%w: image %q looks like a flag", ErrUnsafe, c.Image)
	}
	if c.RequireDigest && !strings.Contains(c.Image, "@sha256:") {
		return nil, fmt.Errorf("%w: %s", ErrNotPinned, c.Image)
	}
	user := or(c.User, "65534:65534")
	if u := strings.SplitN(user, ":", 2)[0]; u == "root" || u == "0" || u == "" {
		return nil, fmt.Errorf("%w: user %q is root", ErrUnsafe, user)
	}
	pids := c.PidsLimit
	if pids <= 0 {
		pids = 128
	}
	mem := or(c.Memory, "512m")
	args := []string{
		"run", "--rm",
		"--network", "none",
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--user", user,
		"--ipc", "none",
		"--pids-limit", strconv.Itoa(pids),
		"--memory", mem, "--memory-swap", mem,
		"--cpus", or(c.CPUs, "1"),
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=" + or(c.TmpfsSize, "64m"),
	}
	if c.Stdin {
		args = append(args, "-i")
	}
	workdir := c.Workdir
	for _, m := range c.Mounts {
		if !filepath.IsAbs(m.Source) || !filepath.IsAbs(m.Target) {
			return nil, fmt.Errorf("%w: mount paths must be absolute (%q -> %q)", ErrUnsafe, m.Source, m.Target)
		}
		src := filepath.Clean(m.Source)
		if strings.HasSuffix(src, ".sock") || strings.Contains(src, ",") || strings.Contains(m.Target, ",") {
			return nil, fmt.Errorf("%w: refusing to mount %s", ErrUnsafe, src)
		}
		for _, f := range forbiddenMount {
			if src == f {
				return nil, fmt.Errorf("%w: refusing to mount %s", ErrUnsafe, src)
			}
		}
		opt := "ro"
		if m.Writable {
			opt = "rw"
		}
		args = append(args, "--mount", "type=bind,source="+src+",target="+filepath.Clean(m.Target)+","+opt)
		if workdir == "" {
			workdir = filepath.Clean(m.Target)
		}
	}
	args = append(args, "--workdir", or(workdir, "/tmp"))
	for _, e := range c.Env {
		k, _, ok := strings.Cut(e, "=")
		if !ok || k == "" || strings.HasPrefix(e, "-") {
			return nil, fmt.Errorf("%w: env entry %q must be KEY=VALUE", ErrUnsafe, e)
		}
		args = append(args, "--env", e)
	}
	return append(append(args, c.Image), argv...), nil
}

// Command returns an *exec.Cmd running argv inside the sandbox. The
// caller starts it (and should set a context deadline).
func Command(ctx context.Context, c Config, argv ...string) (*exec.Cmd, error) {
	args, err := Args(c, argv...)
	if err != nil {
		return nil, err
	}
	rt := or(c.Runtime, "docker")
	if rt != "docker" && rt != "podman" {
		return nil, fmt.Errorf("%w: runtime %q (want docker or podman)", ErrUnsafe, rt)
	}
	cmd := exec.CommandContext(ctx, rt, args...)
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin"}
	return cmd, nil
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
