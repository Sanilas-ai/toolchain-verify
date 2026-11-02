package agent

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/Sanilas-ai/toolchain-verify/internal/version"
)

type watched struct {
	eco, name string
	stack     *Stack   // nil for blocklist-only entries
	blocked   *Blocked // non-nil if blocklisted
}

func watchList(db *DB) map[string]*watched {
	w := map[string]*watched{}
	for i := range db.Stacks {
		s := &db.Stacks[i]
		for _, p := range s.Packages {
			w[s.Ecosystem+":"+normPkg(s.Ecosystem, p)] = &watched{eco: s.Ecosystem, name: p, stack: s}
		}
	}
	for i := range db.Blocklist {
		b := &db.Blocklist[i]
		k := b.Ecosystem + ":" + normPkg(b.Ecosystem, b.Name)
		if e, ok := w[k]; ok {
			e.blocked = b
		} else {
			w[k] = &watched{eco: b.Ecosystem, name: b.Name, blocked: b}
		}
	}
	return w
}

func imageList(db *DB) map[string]*Stack {
	m := map[string]*Stack{}
	for i := range db.Stacks {
		for _, img := range db.Stacks[i].DockerImages {
			m[strings.ToLower(img)] = &db.Stacks[i]
		}
	}
	return m
}

// inventory finds installed / pinned agent stacks without executing anything.
func inventory(r *resolved, db *DB, c *collector, rep *Report) []Install {
	w := watchList(db)
	images := imageList(db)
	var out []Install
	add := func(eco, name, ver, path, source string) {
		e, ok := w[eco+":"+normPkg(eco, name)]
		if !ok {
			return
		}
		in := Install{Package: name, Version: ver, Path: path, Source: source}
		if e.stack != nil {
			in.Stack = e.stack.Name
		}
		if e.blocked != nil {
			c.add(Finding{Rule: "supply.blocklisted", Severity: SevFail, Path: path,
				Message: fmt.Sprintf("%s package %q is on the blocklist: %s", eco, name, e.blocked.Reason), Refs: e.blocked.Refs,
				Fix: "remove it, then treat this environment's secrets as exposed"})
		}
		out = append(out, in)
	}
	st := &walkStats{}
	for _, root := range r.inventory {
		if _, err := os.Lstat(root); err != nil {
			continue
		}
		rep.Scanned = append(rep.Scanned, root)
		r.walk(root, r.inventoryDepth, nil, st, func(p string, d fs.DirEntry) error {
			name := d.Name()
			if d.IsDir() {
				switch {
				case name == "node_modules":
					scanNodeModules(p, w, add)
					return filepath.SkipDir
				case name == "site-packages" || name == "dist-packages":
					scanSitePackages(r, c, p, w, add)
					return filepath.SkipDir
				}
				return nil
			}
			switch {
			case name == "package-lock.json" || name == "npm-shrinkwrap.json":
				scanPackageLock(p, add)
			case name == "pnpm-lock.yaml":
				scanPnpmLock(p, w, add)
			case name == "poetry.lock" || name == "uv.lock" || name == "pdm.lock":
				scanTOMLLock(p, add)
			case strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt"):
				scanRequirements(p, add)
			case name == "Dockerfile" || strings.HasSuffix(name, ".Dockerfile") || strings.HasPrefix(name, "Dockerfile.") ||
				strings.HasPrefix(name, "docker-compose") || strings.HasPrefix(name, "compose.") && (strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")):
				scanImages(c, p, images, func(s *Stack, tag string) {
					in := Install{Stack: s.Name, Package: s.Packages[0], Version: tag, Path: p, Source: "image"}
					out = append(out, in)
				})
			}
			return nil
		})
	}
	if st.truncated {
		c.add(Finding{Rule: "scan.truncated", Severity: SevWarn, Message: fmt.Sprintf("inventory stopped after %d entries; results are incomplete", r.maxEntries),
			Fix: "narrow agent.inventory_paths or lower agent.inventory_depth"})
	}
	return out
}

func readLimited(p string, n int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, n))
}

func scanNodeModules(dir string, w map[string]*watched, add func(eco, name, ver, path, source string)) {
	for _, e := range w {
		if e.eco != "npm" {
			continue
		}
		pj := filepath.Join(dir, filepath.FromSlash(e.name), "package.json")
		if b, err := readLimited(pj, 1<<20); err == nil {
			var meta struct{ Name, Version string }
			if json.Unmarshal(b, &meta) == nil && meta.Version != "" {
				add("npm", e.name, meta.Version, filepath.Dir(pj), "node_modules")
			}
		}
	}
	// pnpm virtual store: node_modules/.pnpm/<name>@<ver>[_peer]/node_modules/<name>
	ents, err := os.ReadDir(filepath.Join(dir, ".pnpm"))
	if err != nil {
		return
	}
	for _, ent := range ents {
		n := ent.Name()
		i := strings.LastIndex(n, "@")
		if i <= 0 {
			continue
		}
		pkg := strings.ReplaceAll(n[:i], "+", "/")
		ver := n[i+1:]
		if j := strings.IndexAny(ver, "_("); j >= 0 {
			ver = ver[:j]
		}
		if _, ok := w["npm:"+pkg]; ok {
			add("npm", pkg, ver, filepath.Join(dir, ".pnpm", n), "pnpm")
		}
	}
}

var distInfoRe = regexp.MustCompile(`^(.+?)-([0-9][^-]*?)(\.dist-info|\.egg-info|-py\d.*\.egg-info)$`)

func scanSitePackages(r *resolved, c *collector, dir string, w map[string]*watched, add func(eco, name, ver, path, source string)) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, ent := range ents {
		n := ent.Name()
		if m := distInfoRe.FindStringSubmatch(n); m != nil {
			if _, ok := w["pypi:"+normPkg("pypi", m[1])]; ok {
				add("pypi", m[1], m[2], filepath.Join(dir, n), "dist-info")
			}
			continue
		}
		if r.supplyChain && strings.HasSuffix(n, ".pth") && !ent.IsDir() {
			checkPth(c, filepath.Join(dir, n))
		}
	}
}

func scanPackageLock(p string, add func(eco, name, ver, path, source string)) {
	b, err := readLimited(p, 64<<20)
	if err != nil {
		return
	}
	var lock struct {
		Packages     map[string]struct{ Version string } `json:"packages"`
		Dependencies map[string]struct{ Version string } `json:"dependencies"`
	}
	if json.Unmarshal(b, &lock) != nil {
		return
	}
	for k, v := range lock.Packages {
		i := strings.LastIndex(k, "node_modules/")
		if i < 0 {
			continue
		}
		add("npm", k[i+len("node_modules/"):], v.Version, p, "lockfile")
	}
	for k, v := range lock.Dependencies {
		add("npm", k, v.Version, p, "lockfile")
	}
}

func scanPnpmLock(p string, w map[string]*watched, add func(eco, name, ver, path, source string)) {
	b, err := readLimited(p, 64<<20)
	if err != nil {
		return
	}
	for _, e := range w {
		if e.eco != "npm" {
			continue
		}
		re := regexp.MustCompile(`(?m)^\s+['"]?/?` + regexp.QuoteMeta(e.name) + `@(\d[^:('"\s]*)`)
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			add("npm", e.name, m[1], p, "lockfile")
		}
	}
}

func scanTOMLLock(p string, add func(eco, name, ver, path, source string)) {
	b, err := readLimited(p, 64<<20)
	if err != nil {
		return
	}
	var lock struct {
		Package []struct{ Name, Version string } `toml:"package"`
	}
	if _, err := toml.Decode(string(b), &lock); err != nil {
		return
	}
	for _, pk := range lock.Package {
		add("pypi", pk.Name, pk.Version, p, "lockfile")
	}
}

var reqRe = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([0-9][^\s;#,]*)`)

func scanRequirements(p string, add func(eco, name, ver, path, source string)) {
	f, err := os.Open(p)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, 8<<20))
	for sc.Scan() {
		if m := reqRe.FindStringSubmatch(sc.Text()); m != nil {
			add("pypi", m[1], m[2], p, "requirements")
		}
	}
}

var imageRe = regexp.MustCompile(`(?i)(?:^|[\s"'=:])((?:docker\.io/)?[a-z0-9][a-z0-9._/-]*?)(?::([A-Za-z0-9][A-Za-z0-9._-]*))?(?:@sha256:[0-9a-f]{64})?(?:["'\s]|$)`)

func scanImages(c *collector, p string, images map[string]*Stack, found func(*Stack, string)) {
	b, err := readLimited(p, 4<<20)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "#") {
			continue
		}
		lower := strings.ToLower(l)
		if !strings.Contains(lower, "image:") && !strings.HasPrefix(lower, "from ") {
			continue
		}
		for _, m := range imageRe.FindAllStringSubmatch(l, -1) {
			repo := strings.TrimPrefix(strings.ToLower(m[1]), "docker.io/")
			s, ok := images[repo]
			if !ok {
				continue
			}
			tag := m[2]
			if tag == "" || strings.EqualFold(tag, "latest") || !looksLikeVersion(tag) {
				c.add(Finding{Rule: "stack.image-unpinned", Severity: SevWarn, Path: p,
					Message: fmt.Sprintf("%s image %s is not pinned to a version (tag %q); cannot verify it against advisories", s.Name, repo, orLatest(tag)),
					Fix:     "pin an explicit fixed version tag (and ideally a digest)"})
				continue
			}
			found(s, strings.TrimPrefix(tag, "v"))
		}
	}
}

func orLatest(t string) string {
	if t == "" {
		return "latest"
	}
	return t
}

func looksLikeVersion(t string) bool {
	_, err := parsePkgVersion(strings.TrimPrefix(t, "v"))
	return err == nil
}

// parsePkgVersion parses npm/PEP 440-ish versions leniently.
func parsePkgVersion(s string) (version.Version, error) {
	s = strings.TrimSpace(s)
	if v, err := version.Parse(s); err == nil {
		return v, nil
	}
	return version.Extract(s)
}
