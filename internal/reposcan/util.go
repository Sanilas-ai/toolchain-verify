package reposcan

import (
	"bytes"
	"io"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }
func sortStrings(s []string)         { sort.Strings(s) }

// isTestishPath reports paths that commonly hold protocol/fixtures data
// where Unicode Tag code points appear without being agent instructions
// (WPT URL tests, testdata corpora, ...).
func isTestishPath(rel string) bool {
	rel = strings.ToLower(filepath.ToSlash(rel))
	parts := strings.Split(rel, "/")
	for _, p := range parts {
		switch p {
		case "test", "tests", "testing", "testdata", "fixtures", "fixture",
			"__tests__", "spec", "specs", "wpt", "web-platform-tests",
			"expectations", "golden", "goldens", "corpus", "samples":
			return true
		}
	}
	base := path.Base(rel)
	if strings.HasSuffix(base, "_test.go") || strings.HasSuffix(base, ".test.js") ||
		strings.HasSuffix(base, ".test.ts") || strings.HasSuffix(base, ".spec.ts") ||
		strings.HasSuffix(base, ".spec.js") || strings.Contains(base, ".test.") {
		return true
	}
	return false
}
