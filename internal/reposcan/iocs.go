package reposcan

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

//go:embed iocs.toml
var embeddedIOCs []byte

// IOCDB is the versioned indicator database.
type IOCDB struct {
	Version string `toml:"version"`
	Updated string `toml:"updated"`
	IOCs    []IOC  `toml:"ioc"`
}

// IOC is one campaign's indicators.
type IOC struct {
	ID             string       `toml:"id"`
	Title          string       `toml:"title"`
	Source         string       `toml:"source"`
	Published      string       `toml:"published"`
	Domains        []string     `toml:"domains"`
	Strings        []string     `toml:"strings"`
	MCPServerNames []string     `toml:"mcp_server_names"`
	Paths          []string     `toml:"paths"`
	Packages       []IOCPackage `toml:"packages"`
	SHA256         []string     `toml:"sha256"`
	Note           string       `toml:"note"`
}

// IOCPackage is a malicious package name (and versions, if only some are).
type IOCPackage struct {
	Ecosystem string   `toml:"ecosystem"`
	Name      string   `toml:"name"`
	Versions  []string `toml:"versions"`
}

var hexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ParseIOCs strictly decodes and validates an IOC file.
func ParseIOCs(b []byte) (*IOCDB, error) {
	var db IOCDB
	md, err := toml.Decode(string(b), &db)
	if err != nil {
		return nil, err
	}
	if und := md.Undecoded(); len(und) > 0 {
		return nil, fmt.Errorf("unknown keys: %v", und)
	}
	if db.Version == "" || db.Updated == "" {
		return nil, fmt.Errorf("version and updated are required")
	}
	for i := range db.IOCs {
		e := &db.IOCs[i]
		if e.ID == "" || !strings.HasPrefix(e.Source, "https://") || e.Published == "" {
			return nil, fmt.Errorf("ioc %d: id, https source and published are required", i)
		}
		for j, d := range e.Domains {
			e.Domains[j] = strings.ToLower(strings.ReplaceAll(d, "[.]", "."))
		}
		for _, h := range e.SHA256 {
			if !hexRe.MatchString(h) {
				return nil, fmt.Errorf("ioc %s: bad sha256 %q", e.ID, h)
			}
		}
		for _, p := range e.Packages {
			switch p.Ecosystem {
			case "rubygems", "pypi", "npm":
			default:
				return nil, fmt.Errorf("ioc %s: unsupported ecosystem %q", e.ID, p.Ecosystem)
			}
		}
	}
	return &db, nil
}

// EmbeddedIOCs returns the built-in DB.
func EmbeddedIOCs() (*IOCDB, error) { return ParseIOCs(embeddedIOCs) }

// LoadIOCs merges extra IOC files into the embedded DB.
func LoadIOCs(files ...string) (*IOCDB, error) {
	db, err := EmbeddedIOCs()
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		extra, err := ParseIOCs(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		db.IOCs = append(db.IOCs, extra.IOCs...)
		db.Version += "+" + extra.Version
	}
	return db, nil
}

// matchText returns the id of an IOC whose domain occurs in canonical text.
func (db *IOCDB) matchText(canon string) string {
	for _, e := range db.IOCs {
		for _, d := range e.Domains {
			if strings.Contains(canon, d) {
				return e.ID + " (" + defang(d) + ")"
			}
		}
	}
	return ""
}

func (db *IOCDB) mcpName(name string) string {
	for _, e := range db.IOCs {
		for _, n := range e.MCPServerNames {
			if strings.EqualFold(n, name) {
				return e.ID
			}
		}
	}
	return ""
}

func (db *IOCDB) pathIOC(p string) string {
	for _, e := range db.IOCs {
		for _, x := range e.Paths {
			if strings.EqualFold(x, p) {
				return e.ID
			}
		}
	}
	return ""
}

func defang(d string) string { return strings.ReplaceAll(d, ".", "[.]") }

// scanIOCText: domains (fail in control/script context, warn elsewhere;
// defanged mentions in docs are info), weak strings (warn when two or more
// co-occur), package names in lockfiles/manifests, IOC paths.
func (s *scanner) scanIOCText(rel, kind string, b []byte) {
	lower := strings.ToLower(string(b))
	code := kind != "" || isScriptName(rel)
	for _, e := range s.opt.IOCs.IOCs {
		for _, d := range e.Domains {
			if i := strings.Index(lower, d); i >= 0 {
				sev := SevWarn
				if code {
					sev = SevFail
				}
				s.add(Finding{Rule: "ioc.domain", Severity: sev, Path: rel, Line: lineOf(b, i), Offset: i,
					Evidence: escapeEvidence(defang(snippetAround([]byte(lower), i, 100)), evidenceRunes),
					Message:  "contains " + defang(d) + " from " + e.ID, Refs: []string{e.Source}, Fix: e.Note})
			} else if i := strings.Index(lower, defang(d)); i >= 0 {
				s.add(Finding{Rule: "ioc.domain-mention", Severity: SevInfo, Path: rel, Line: lineOf(b, i), Offset: i,
					Message: "mentions defanged indicator " + defang(d) + " (" + e.ID + "); documentation is fine"})
			}
		}
		var hits []string
		first := -1
		for _, str := range e.Strings {
			if i := strings.Index(lower, strings.ToLower(str)); i >= 0 {
				hits = append(hits, str)
				if first < 0 {
					first = i
				}
			}
		}
		if len(hits) >= 2 || (len(hits) == 1 && code) {
			s.add(Finding{Rule: "ioc.strings", Severity: SevWarn, Path: rel, Line: lineOf(b, first), Offset: first,
				Message: fmt.Sprintf("indicator strings of %s: %s (weak alone; check together with other findings)", e.ID, strings.Join(hits, ", ")),
				Refs:    []string{e.Source}})
		}
		for _, p := range e.Paths {
			if strings.EqualFold(rel, p) {
				s.add(Finding{Rule: "ioc.path", Severity: SevWarn, Path: rel,
					Message: "file at a persistence path used by " + e.ID + "; fails only if a hook/MCP/task runs it",
					Refs:    []string{e.Source}})
			}
		}
		s.packageIOCs(rel, lower, b, e)
	}
}

func isScriptName(rel string) bool {
	switch strings.ToLower(path.Ext(rel)) {
	case ".js", ".mjs", ".cjs", ".ts", ".py", ".rb", ".sh", ".bash", ".ps1", ".pl", ".go", ".yml", ".yaml", ".json", ".toml":
		return true
	}
	return false
}

func ecosystemOf(rel string) string {
	base := strings.ToLower(path.Base(rel))
	switch {
	case base == "gemfile" || base == "gemfile.lock" || strings.HasSuffix(base, ".gemspec") || base == "gems.rb" || base == "gems.locked":
		return "rubygems"
	case base == "package.json" || base == "package-lock.json" || base == "npm-shrinkwrap.json" || base == "yarn.lock" || base == "pnpm-lock.yaml" || base == "bun.lock":
		return "npm"
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"), base == "pyproject.toml", base == "poetry.lock", base == "uv.lock",
		base == "pipfile", base == "pipfile.lock", base == "setup.py", base == "setup.cfg", base == "pdm.lock", base == "pylock.toml":
		return "pypi"
	}
	return ""
}

func (s *scanner) packageIOCs(rel, lower string, b []byte, e IOC) {
	eco := ecosystemOf(rel)
	if eco == "" {
		return
	}
	for _, p := range e.Packages {
		if p.Ecosystem != eco {
			continue
		}
		name := strings.ToLower(p.Name)
		re := regexp.MustCompile(`(^|[^a-z0-9_.-])` + regexp.QuoteMeta(name) + `([^a-z0-9_-]|$)`)
		loc := re.FindStringIndex(lower)
		if loc == nil && eco == "pypi" {
			alt := strings.ReplaceAll(name, "-", "_")
			loc = regexp.MustCompile(`(^|[^a-z0-9_.-])` + regexp.QuoteMeta(alt) + `([^a-z0-9-]|$)`).FindStringIndex(lower)
		}
		if loc == nil {
			continue
		}
		window := lower[loc[0]:min(len(lower), loc[1]+200)]
		sev, which := SevWarn, "name"
		if len(p.Versions) == 0 {
			sev, which = SevFail, "package"
		}
		for _, v := range p.Versions {
			if strings.Contains(window, v) {
				sev, which = SevFail, "version "+v
				break
			}
		}
		s.add(Finding{Rule: "ioc.package", Severity: sev, Path: rel, Line: lineOf(b, loc[0]), Offset: loc[0],
			Evidence: escapeEvidence(strings.TrimSpace(snippetAround([]byte(lower), loc[0], 80)), 100),
			Message:  fmt.Sprintf("dependency on %s package %s (%s matches %s)", eco, p.Name, which, e.ID),
			Fix:      "if it was ever installed: " + e.Note, Refs: []string{e.Source}})
	}
}

// hashIOCFile hashes archives/packages (bounded) and compares to IOCs.
func (s *scanner) hashIOCFile(p, rel string) {
	if !s.opt.IOCs.hasHashes() {
		return
	}
	b, _, partial, err := s.readBounded(p, 64<<20)
	if err != nil || partial {
		return
	}
	s.hashIOCBytes(rel, b, false)
}

func (db *IOCDB) hasHashes() bool {
	for _, e := range db.IOCs {
		if len(e.SHA256) > 0 {
			return true
		}
	}
	return false
}

func (s *scanner) hashIOCBytes(rel string, b []byte, partial bool) {
	if partial || len(b) == 0 {
		return
	}
	sum := sha256.Sum256(b)
	h := hex.EncodeToString(sum[:])
	for _, e := range s.opt.IOCs.IOCs {
		for _, x := range e.SHA256 {
			if x == h {
				s.add(Finding{Rule: "ioc.sha256", Severity: SevFail, Path: rel, Evidence: h,
					Message: "file hash matches a known-malicious artifact of " + e.ID + "; do not run, install or open it with an agent",
					Fix:     e.Note, Refs: []string{e.Source}})
			}
		}
	}
}
