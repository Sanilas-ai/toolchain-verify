package agent

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// skipDirNames are never descended into by any walk.
var skipDirNames = map[string]bool{
	".git": true, ".hg": true, ".svn": true, "__pycache__": true,
	".cache": true, ".npm": true, ".pnpm-store": true, ".gradle": true, ".m2": true,
	"proc": false, // only skipped at "/" level (see walk)
}

type walkStats struct {
	entries   int
	truncated bool
}

// walk visits root up to depth levels (root = 0) without following
// symlinks, skipping VCS internals, credential stores and the given
// excluded subtrees. visit may return filepath.SkipDir for directories.
func (r *resolved) walk(root string, depth int, exclude []string, st *walkStats, visit func(path string, d fs.DirEntry) error) {
	root = filepath.Clean(root)
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() {
		return
	}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		st.entries++
		if st.entries > r.maxEntries {
			st.truncated = true
			return filepath.SkipAll
		}
		if d.IsDir() && p != root {
			if skipDirNames[d.Name()] {
				return filepath.SkipDir
			}
			if _, bad := withinAny(p, r.credDirs); bad {
				return filepath.SkipDir
			}
			for _, ex := range exclude {
				if within(p, ex) {
					return filepath.SkipDir
				}
			}
			rel, _ := filepath.Rel(root, p)
			if strings.Count(rel, string(filepath.Separator))+1 > depth {
				return filepath.SkipDir
			}
		}
		return visit(p, d)
	})
}

// matchInstruction reports whether path is an agent instruction file.
func matchInstruction(path string, patterns []string) bool {
	return matchPatterns(path, patterns)
}

func matchPatterns(path string, patterns []string) bool {
	segs := strings.Split(filepath.ToSlash(filepath.Clean(path)), "/")
	base := strings.ToLower(segs[len(segs)-1])
	nbase := strings.ToLower(normalizeDownloadName(segs[len(segs)-1]))
	for _, pat := range patterns {
		pat = strings.ToLower(filepath.ToSlash(pat))
		if !strings.Contains(pat, "/") {
			if ok, _ := filepath.Match(pat, base); ok {
				return true
			}
			if ok, _ := filepath.Match(pat, nbase); ok {
				return true
			}
			continue
		}
		ps := strings.Split(pat, "/")
		if len(ps) > len(segs) {
			continue
		}
		tail := segs[len(segs)-len(ps):]
		ok := true
		for i := range ps {
			name := strings.ToLower(tail[i])
			if i == len(ps)-1 {
				m1, _ := filepath.Match(ps[i], name)
				m2, _ := filepath.Match(ps[i], strings.ToLower(normalizeDownloadName(tail[i])))
				if !m1 && !m2 {
					ok = false
				}
				continue
			}
			if m, _ := filepath.Match(ps[i], name); !m {
				ok = false
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// normalizeDownloadName strips the duplicate suffix browsers add:
// "AGENTS (1).md" -> "AGENTS.md", "AGENTS(2).md" -> "AGENTS.md".
func normalizeDownloadName(name string) string {
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	if i := strings.LastIndex(stem, "("); i > 0 && strings.HasSuffix(stem, ")") {
		num := stem[i+1 : len(stem)-1]
		if num != "" && strings.Trim(num, "0123456789") == "" {
			return strings.TrimRight(stem[:i], " ") + ext
		}
	}
	return name
}
