package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"

	"strings"
	"time"
)

// Host inventory: read-only sources outside the directory walk.
//
//   - snap: /snap/<name>/current payloads (site-packages, node_modules) are
//     added as inventory roots.
//   - systemd: unit files are parsed (never executed); ExecStart binaries in
//     a venv or node_modules and WorkingDirectory become inventory roots,
//     `docker|podman run IMAGE:TAG` is matched against stack images.
//   - Docker / Podman Engine API over a unix socket, GET only: local image
//     tags and containers (incl. stopped ones). For containers of a known
//     stack only the variables named by an advisory's escalate_env are
//     looked at; no other environment value is kept or printed.

// DefaultSystemdDirs are the unit directories read by the host inventory.
func DefaultSystemdDirs(home string) []string {
	return []string{
		"/etc/systemd/system", "/run/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system",
		"/etc/systemd/user", "/usr/lib/systemd/user", filepath.Join(home, ".config", "systemd", "user"),
	}
}

// hostInventory returns extra inventory roots and installs seen through
// systemd units and the container engine.
func hostInventory(r *resolved, db *DB, c *collector, rep *Report) (roots []string, installs []Install) {
	images := imageList(db)
	escalate := escalateNames(db)
	if rs := snapRoots(r.snapRoot); len(rs) > 0 {
		rep.Scanned = append(rep.Scanned, r.snapRoot)
		roots = append(roots, rs...)
	}
	sr, si := scanSystemd(r, c, db, images, escalate)
	roots = append(roots, sr...)
	installs = append(installs, si...)
	if len(sr)+len(si) > 0 {
		rep.Scanned = append(rep.Scanned, "systemd")
	}
	installs = append(installs, scanDocker(r, c, rep, images, escalate)...)
	return roots, installs
}

func escalateNames(db *DB) map[string]bool {
	m := map[string]bool{}
	for _, a := range db.Advisories {
		if name, _, ok := strings.Cut(a.EscalateEnv, "="); ok && name != "" {
			m[name] = true
		}
	}
	return m
}

var snapPayloadGlobs = []string{
	"lib/python3*/site-packages", "usr/lib/python3*/site-packages", "usr/lib/python3/dist-packages",
	"usr/local/lib/python3*/dist-packages", "lib/node_modules", "usr/lib/node_modules", "usr/local/lib/node_modules",
}

func snapRoots(snapRoot string) []string {
	ents, err := os.ReadDir(snapRoot)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() || e.Name() == "bin" {
			continue
		}
		base := filepath.Join(snapRoot, e.Name(), "current")
		for _, g := range snapPayloadGlobs {
			m, _ := filepath.Glob(filepath.Join(base, filepath.FromSlash(g)))
			out = append(out, m...)
		}
	}
	return out
}

// splitImageRef splits "docker.io/flowiseai/flowise:3.1.3@sha256:..." into
// ("flowiseai/flowise", "3.1.3").
func splitImageRef(ref string) (repo, tag string) {
	ref = strings.TrimSpace(ref)
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref, tag = ref[:i], ref[i+1:]
	}
	repo = strings.ToLower(ref)
	repo = strings.TrimPrefix(repo, "docker.io/")
	repo = strings.TrimPrefix(repo, "index.docker.io/")
	return repo, tag
}

// imageInstall matches an image reference against stack images. It reports
// unpinned tags and returns ok=false when nothing (checkable) matched.
func imageInstall(c *collector, images map[string]*Stack, ref, path, source string) (Install, bool) {
	repo, tag := splitImageRef(ref)
	s, ok := images[repo]
	if !ok {
		return Install{}, false
	}
	if tag == "" || strings.EqualFold(tag, "latest") || !looksLikeVersion(tag) {
		c.add(Finding{Rule: "stack.image-unpinned", Severity: SevWarn, Path: path,
			Message: fmt.Sprintf("%s image %s is not pinned to a version (tag %q); cannot verify it against advisories", s.Name, repo, orLatest(tag)),
			Fix:     "pin an explicit fixed version tag (and ideally a digest)"})
		return Install{}, false
	}
	return Install{Stack: s.Name, Package: s.Packages[0], Version: strings.TrimPrefix(tag, "v"), Path: path, Source: source}, true
}

// ------------------------------------------------------------- systemd

var execKeys = map[string]bool{"ExecStart": true, "ExecStartPre": true, "ExecStartPost": true, "ExecReload": true}

type unitFile struct {
	path    string
	execs   [][]string
	workdir []string
	env     map[string]string
}

func parseUnit(path string, escalate map[string]bool) *unitFile {
	b, err := readLimited(path, 256<<10)
	if err != nil {
		return nil
	}
	u := &unitFile{path: path, env: map[string]string{}}
	sc := bufio.NewScanner(strings.NewReader(strings.ReplaceAll(string(b), "\\\n", " ")))
	sc.Buffer(make([]byte, 64<<10), 512<<10)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' || line[0] == '[' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch {
		case execKeys[k]:
			v = strings.TrimLeft(v, "-@:+!")
			if f := strings.Fields(v); len(f) > 0 {
				u.execs = append(u.execs, f)
			}
		case k == "WorkingDirectory":
			if w := strings.TrimPrefix(v, "-"); filepath.IsAbs(w) {
				u.workdir = append(u.workdir, filepath.Clean(w))
			}
		case k == "Environment":
			for _, kv := range strings.Fields(v) {
				kv = strings.Trim(kv, `"'`)
				if n, val, ok := strings.Cut(kv, "="); ok && escalate[n] {
					u.env[n] = val
				}
			}
		}
	}
	return u
}

// stackWords maps executable / package names to stacks for unit matching.
func stackWords(db *DB) map[string]*Stack {
	m := map[string]*Stack{}
	for i := range db.Stacks {
		s := &db.Stacks[i]
		m[strings.ToLower(s.Name)] = s
		for _, p := range s.Packages {
			m[strings.ToLower(p)] = s
		}
	}
	// Console scripts whose name differs from the package.
	if s, ok := m["praisonaiagents"]; ok {
		m["praisonai"] = s
	}
	return m
}

func scanSystemd(r *resolved, c *collector, db *DB, images map[string]*Stack, escalate map[string]bool) (roots []string, installs []Install) {
	words := stackWords(db)
	seen := map[string]bool{}
	n := 0
	for _, dir := range r.systemdDirs {
		if _, bad := r.credentialHit(dir); bad {
			continue
		}
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			name := e.Name()
			if !strings.HasSuffix(name, ".service") || e.IsDir() {
				continue
			}
			p := filepath.Join(dir, name)
			st, err := os.Stat(p) // units are often symlinks into /lib
			if err != nil || !st.Mode().IsRegular() {
				continue
			}
			if n++; n > 5000 {
				return roots, installs
			}
			real := realOrSelf(p)
			if seen[real] {
				continue
			}
			seen[real] = true
			u := parseUnit(p, escalate)
			if u == nil {
				continue
			}
			mentioned := false
			for _, args := range u.execs {
				ex := strings.ToLower(filepath.Base(args[0]))
				if (ex == "docker" || ex == "podman") && len(args) > 1 {
					env := map[string]string{}
					for k, v := range u.env {
						env[k] = v
					}
					for i := 1; i < len(args); i++ {
						a := args[i]
						if (a == "-e" || a == "--env") && i+1 < len(args) {
							if k, v, ok := strings.Cut(args[i+1], "="); ok && escalate[k] {
								env[k] = v
							}
						}
						if in, ok := imageInstall(c, images, strings.Trim(a, `"'`), p, "systemd"); ok {
							in.Env = env
							installs = append(installs, in)
							mentioned = true
						}
					}
					continue
				}
				if filepath.IsAbs(args[0]) {
					roots = append(roots, execRoots(args[0])...)
				}
				for _, a := range args {
					w := strings.ToLower(filepath.Base(strings.Trim(a, `"'`)))
					w = strings.TrimSuffix(strings.TrimSuffix(w, ".js"), ".py")
					if s, ok := words[w]; ok {
						mentioned = true
						sev, how := SevInfo, "runs"
						if s.CanExec {
							sev, how = SevWarn, "runs exec-capable agent stack"
						}
						c.add(Finding{Rule: "stack.service", Severity: sev, Path: p,
							Message: fmt.Sprintf("systemd unit %s %s %s directly on the host (%s)", name, how, s.Name, filepath.Base(args[0])),
							Fix:     "run it in a disposable non-root container with an empty env, or stop and disable the unit; make sure its install path is in agent.inventory_paths so its version is checked"})
						break
					}
				}
			}
			if mentioned {
				for _, w := range u.workdir {
					roots = append(roots, w)
				}
			}
		}
	}
	return roots, installs
}

// execRoots derives inventory roots from an executable path: the venv of
// /x/venv/bin/langflow, or the node_modules of /x/node_modules/.bin/flowise.
func execRoots(exe string) []string {
	exe = filepath.Clean(exe)
	var out []string
	if i := strings.LastIndex(exe, string(filepath.Separator)+"node_modules"+string(filepath.Separator)); i >= 0 {
		out = append(out, exe[:i+len("/node_modules")])
	}
	if filepath.Base(filepath.Dir(exe)) == "bin" {
		prefix := filepath.Dir(filepath.Dir(exe))
		if prefix != "/" && prefix != "/usr" && prefix != "/usr/local" {
			for _, g := range []string{"lib/python3*/site-packages", "lib/node_modules"} {
				m, _ := filepath.Glob(filepath.Join(prefix, filepath.FromSlash(g)))
				out = append(out, m...)
			}
		}
	}
	return out
}

// -------------------------------------------------------------- docker

var containerIDRe = regexp.MustCompile(`^[0-9a-f]{12,64}$`)

func (r *resolved) engineSocket() string {
	if r.dockerSocket == "off" {
		return ""
	}
	if r.dockerSocket != "" {
		return r.dockerSocket
	}
	if v := r.getenv("DOCKER_HOST"); v != "" {
		if s, ok := strings.CutPrefix(v, "unix://"); ok {
			return s
		}
		return "" // never talk to a remote engine
	}
	cands := []string{"/var/run/docker.sock", "/run/podman/podman.sock"}
	if x := r.getenv("XDG_RUNTIME_DIR"); filepath.IsAbs(x) {
		cands = append(cands, filepath.Join(x, "docker.sock"), filepath.Join(x, "podman", "podman.sock"))
	}
	for _, s := range cands {
		if st, err := os.Stat(s); err == nil && st.Mode()&os.ModeSocket != 0 {
			return s
		}
	}
	return ""
}

func scanDocker(r *resolved, c *collector, rep *Report, images map[string]*Stack, escalate map[string]bool) []Install {
	sock := r.engineSocket()
	if sock == "" {
		return nil
	}
	if _, err := os.Stat(sock); err != nil {
		return nil
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}}
	get := func(path string, v any) error {
		resp, err := client.Get("http://engine" + path)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
		}
		return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(v)
	}
	var imgs []struct {
		RepoTags []string `json:"RepoTags"`
	}
	if err := get("/images/json", &imgs); err != nil {
		c.add(Finding{Rule: "inventory.engine-unavailable", Severity: SevInfo, Path: sock,
			Message: fmt.Sprintf("cannot query the container engine (%v); local images and containers were not checked", err),
			Fix:     "run as a user that may read the socket, set agent.docker_socket, or pass --no-host-inventory"})
		return nil
	}
	rep.Scanned = append(rep.Scanned, "engine:"+sock)
	var out []Install
	for _, im := range imgs {
		for _, ref := range im.RepoTags {
			if in, ok := imageInstall(c, images, ref, "docker image "+ref, "docker-image"); ok {
				out = append(out, in)
			}
		}
	}
	var ctrs []struct {
		ID    string   `json:"Id"`
		Image string   `json:"Image"`
		Names []string `json:"Names"`
		State string   `json:"State"`
	}
	if err := get("/containers/json?all=1", &ctrs); err != nil {
		return out
	}
	for _, ct := range ctrs {
		name := ct.ID
		if len(ct.Names) > 0 {
			name = strings.TrimPrefix(ct.Names[0], "/")
		} else if len(name) > 12 {
			name = name[:12]
		}
		path := fmt.Sprintf("docker container %s (%s, %s)", name, ct.Image, ct.State)
		in, ok := imageInstall(c, images, ct.Image, path, "docker-container")
		if !ok {
			continue
		}
		if containerIDRe.MatchString(ct.ID) && len(escalate) > 0 {
			var insp struct {
				Config struct {
					Env []string `json:"Env"`
				} `json:"Config"`
			}
			if get("/containers/"+ct.ID+"/json", &insp) == nil {
				in.Env = map[string]string{}
				for _, kv := range insp.Config.Env {
					if k, v, ok := strings.Cut(kv, "="); ok && escalate[k] {
						in.Env[k] = v
					}
				}
			}
		}
		out = append(out, in)
	}
	return out
}
