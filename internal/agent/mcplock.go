package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// MCP server lock file (inspired by mozilla-ai/mcpd): it records, per MCP
// server, the launch package, its exact version and an integrity hash of the
// whole launch spec, so a version drift or a package substitution is caught
// before the server runs. Optionally it also pins tool-definition hashes
// (rug-pull detection) alongside.
//
// CWE references:
//   CWE-829  Inclusion of Functionality from Untrusted Control Sphere
//   CWE-494  Download of Code Without Integrity Check
//   CWE-1357 Reliance on Insufficiently Trustworthy Component

// MCPLockVersion is the current lock schema version.
const MCPLockVersion = 1

// MCPLock is the on-disk lock.
type MCPLock struct {
	Version int                     `json:"version"`
	Created string                  `json:"created,omitempty"`
	Servers map[string]MCPLockEntry `json:"servers"`
	Tools   map[string]string       `json:"tools,omitempty"` // tool-id -> sha256
}

// MCPLockEntry pins one server.
type MCPLockEntry struct {
	Package   string   `json:"package,omitempty"`
	Version   string   `json:"version,omitempty"`
	Pinned    bool     `json:"pinned"`
	Integrity string   `json:"integrity"`
	Command   string   `json:"command,omitempty"`
	Args      []string `json:"args,omitempty"`
	URL       string   `json:"url,omitempty"`
}

// LockedServer is a server discovered in the configs, ready to lock.
type LockedServer struct {
	Key       string
	Name      string
	Path      string
	Command   string
	Args      []string
	URL       string
	Package   string
	Version   string
	Pinned    bool
	Integrity string
}

// CollectMCPServers discovers every enabled MCP server across the audited
// config files (same discovery as the agent audit) and derives its launch
// package, version, pinned-ness and integrity hash.
func CollectMCPServers(p *Policy, opt Options) ([]LockedServer, error) {
	r, err := resolve(p, opt)
	if err != nil {
		return nil, err
	}
	byPath := map[string]bool{}
	var paths []string
	addPath := func(ps ...string) {
		for _, p := range ps {
			if !byPath[p] {
				byPath[p] = true
				paths = append(paths, p)
			}
		}
	}
	for _, rel := range DefaultMCPConfigs {
		addPath(filepath.Join(r.home, filepath.FromSlash(rel)))
	}
	for _, rel := range projectMCPConfigs {
		addPath(filepath.Join(r.cwd, filepath.FromSlash(rel)))
	}
	addPath(r.mcpExtra...)
	sort.Strings(paths)

	var out []LockedServer
	keyCount := map[string]int{}
	for _, path := range paths {
		if _, bad := r.credentialFileHit(path); bad {
			continue
		}
		st, err := os.Stat(path)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		b, err := readLimited(path, 16<<20)
		if err != nil {
			continue
		}
		var doc map[string]any
		if strings.HasSuffix(path, ".toml") {
			if _, err := toml.Decode(string(b), &doc); err != nil {
				continue
			}
		} else if err := json.Unmarshal(stripJSONC(b), &doc); err != nil {
			continue
		}
		for _, s := range extractServers(doc) {
			if s.disabled {
				continue
			}
			ls := lockedFromServer(path, s)
			keyCount[ls.Name]++
			out = append(out, ls)
		}
	}
	// Disambiguate colliding names by appending the config path.
	for i := range out {
		if keyCount[out[i].Name] > 1 {
			out[i].Key = out[i].Name + "@" + out[i].Path
		} else {
			out[i].Key = out[i].Name
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func lockedFromServer(path string, s mcpServer) LockedServer {
	ls := LockedServer{Name: s.name, Path: path, Command: s.command, Args: append([]string(nil), s.args...), URL: s.url}
	if s.command != "" {
		cmd := strings.ToLower(filepath.Base(s.command))
		if pkg, pinned := runnerPackage(cmd, s.args); pkg != "" {
			ls.Package, ls.Version = parseNameVersion(pkg)
			ls.Pinned = pinned
		}
	}
	ls.Integrity = specHash(s.command, s.args, s.url)
	return ls
}

// specHash hashes the whole launch spec deterministically.
func specHash(command string, args []string, url string) string {
	h := sha256.New()
	h.Write([]byte(command))
	h.Write([]byte{0})
	for _, a := range args {
		h.Write([]byte(a))
		h.Write([]byte{0})
	}
	h.Write([]byte{0})
	h.Write([]byte(url))
	return hex.EncodeToString(h.Sum(nil))
}

// parseNameVersion splits a runner package spec into name and version.
// "pkg@1.2.3" -> ("pkg","1.2.3"); "@scope/pkg@1.2.3" -> ("@scope/pkg","1.2.3");
// "pkg==1.2.3" -> ("pkg","1.2.3"); "pkg" -> ("pkg","").
func parseNameVersion(p string) (name, version string) {
	if i := strings.Index(p, "=="); i >= 0 {
		return p[:i], p[i+2:]
	}
	scoped := strings.HasPrefix(p, "@")
	body := p
	if scoped {
		body = p[1:]
	}
	if i := strings.LastIndex(body, "@"); i >= 0 {
		name = body[:i]
		version = body[i+1:]
		if scoped {
			name = "@" + name
		}
		return name, version
	}
	return p, ""
}

// NewMCPLock builds a lock from discovered servers.
func NewMCPLock(servers []LockedServer, created string) *MCPLock {
	l := &MCPLock{Version: MCPLockVersion, Created: created, Servers: map[string]MCPLockEntry{}}
	for _, s := range servers {
		l.Servers[s.Key] = MCPLockEntry{
			Package: s.Package, Version: s.Version, Pinned: s.Pinned,
			Integrity: s.Integrity, Command: s.Command, Args: s.Args, URL: s.URL,
		}
	}
	return l
}

// LoadMCPLock reads a lock file.
func LoadMCPLock(path string) (*MCPLock, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var l MCPLock
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if l.Version != MCPLockVersion || l.Servers == nil {
		return nil, fmt.Errorf("%s: not a version %d MCP lock", path, MCPLockVersion)
	}
	return &l, nil
}

// CheckMCPLock compares discovered servers against the lock and returns
// findings. Unpinned servers warn regardless of the lock.
func CheckMCPLock(lock *MCPLock, servers []LockedServer) []Finding {
	var fs []Finding
	cur := map[string]bool{}
	for _, s := range servers {
		cur[s.Key] = true
		if s.Package != "" && !s.Pinned {
			fs = append(fs, Finding{Rule: "mcp.lock-unpinned", Severity: SevWarn, Path: s.Path,
				Message: fmt.Sprintf("server %q launches %q without a pinned version; a new upstream release runs unreviewed at the next start", s.Name, s.Package),
				Fix:     "pin an exact version (npx pkg@1.2.3 / uvx pkg==1.2.3) and record it with `mcp-lock --write`",
				Refs:    []string{"https://cwe.mitre.org/data/definitions/494.html"}})
		}
		e, ok := lock.Servers[s.Key]
		if !ok {
			fs = append(fs, Finding{Rule: "mcp.lock-new", Severity: SevWarn, Path: s.Path,
				Message: fmt.Sprintf("server %q is not in the lock; review it, then re-run `mcp-lock --write`", s.Name),
				Refs:    []string{"https://cwe.mitre.org/data/definitions/829.html"}})
			continue
		}
		if e.Integrity == s.Integrity {
			continue
		}
		msg := fmt.Sprintf("server %q launch spec changed since it was locked", s.Name)
		switch {
		case e.Package != "" && s.Package != "" && e.Package != s.Package:
			msg = fmt.Sprintf("server %q package substituted: locked %q, now %q", s.Name, e.Package, s.Package)
		case e.Version != s.Version:
			msg = fmt.Sprintf("server %q version drift: locked %q, now %q", s.Name, orNone(e.Version), orNone(s.Version))
		}
		fs = append(fs, Finding{Rule: "mcp.lock", Severity: SevFail, Path: s.Path,
			Message: msg + fmt.Sprintf(" (integrity %s… -> %s…)", clip(e.Integrity), clip(s.Integrity)),
			Fix:     "diff the server definition; re-run `mcp-lock --write` only after review",
			Refs:    []string{"https://cwe.mitre.org/data/definitions/829.html", "https://cwe.mitre.org/data/definitions/1357.html"}})
	}
	var removed []string
	for k := range lock.Servers {
		if !cur[k] {
			removed = append(removed, k)
		}
	}
	sort.Strings(removed)
	for _, k := range removed {
		fs = append(fs, Finding{Rule: "mcp.lock-removed", Severity: SevInfo, Path: "",
			Message: fmt.Sprintf("locked server %q is no longer configured", k)})
	}
	sortFindings(fs)
	return fs
}

func clip(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
