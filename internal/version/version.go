// Package version implements lenient semantic-version parsing, extraction of
// versions from tool output, and constraint matching (npm/cargo-like syntax).
package version

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Version is a semantic version. Missing minor/patch components are zero.
type Version struct {
	Major, Minor, Patch int
	Pre                 string // pre-release identifiers, without the leading '-'
}

func (v Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	return s
}

var strictRe = regexp.MustCompile(`^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-?([0-9A-Za-z][0-9A-Za-z.-]*))?(?:\+[0-9A-Za-z.-]+)?$`)

// extractRe finds the first "X.Y" or "X.Y.Z" (with optional pre-release) in free text.
var extractRe = regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?(?:-?((?:alpha|beta|rc|pre|dev)(?:\.?\d+)*|[ab]\d+))?`)

// Parse parses a version string such as "1.2.3", "v1.22", "3.13.0rc1" or
// "2.0.0-beta.1+build5". Build metadata is ignored.
func Parse(s string) (Version, error) {
	s = strings.TrimSpace(s)
	m := strictRe.FindStringSubmatch(s)
	if m == nil {
		return Version{}, fmt.Errorf("invalid version %q", s)
	}
	return fromMatch(m[1], m[2], m[3], m[4])
}

// Extract returns the first version-looking substring of free-form text,
// e.g. "go version go1.22.3 linux/amd64" -> 1.22.3.
func Extract(text string) (Version, error) {
	m := extractRe.FindStringSubmatch(text)
	if m == nil {
		return Version{}, fmt.Errorf("no version found in output %q", truncate(text, 120))
	}
	return fromMatch(m[1], m[2], m[3], m[4])
}

func fromMatch(maj, min, pat, pre string) (Version, error) {
	var v Version
	var err error
	if v.Major, err = atoi(maj); err != nil {
		return v, err
	}
	if v.Minor, err = atoi(min); err != nil {
		return v, err
	}
	if v.Patch, err = atoi(pat); err != nil {
		return v, err
	}
	v.Pre = pre
	return v, nil
}

func atoi(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid number %q", s)
	}
	return n, nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// Compare returns -1, 0 or 1. A pre-release sorts before the release
// (1.0.0-rc1 < 1.0.0); pre-release identifiers compare per SemVer 2.0.
func Compare(a, b Version) int {
	switch {
	case a.Major != b.Major:
		return sign(a.Major - b.Major)
	case a.Minor != b.Minor:
		return sign(a.Minor - b.Minor)
	case a.Patch != b.Patch:
		return sign(a.Patch - b.Patch)
	}
	return comparePre(a.Pre, b.Pre)
}

func comparePre(a, b string) int {
	if a == b {
		return 0
	}
	if a == "" {
		return 1
	}
	if b == "" {
		return -1
	}
	ap, bp := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(ap) && i < len(bp); i++ {
		an, aerr := strconv.Atoi(ap[i])
		bn, berr := strconv.Atoi(bp[i])
		switch {
		case aerr == nil && berr == nil:
			if an != bn {
				return sign(an - bn)
			}
		case aerr == nil:
			return -1 // numeric identifiers sort before alphanumeric
		case berr == nil:
			return 1
		default:
			if c := strings.Compare(ap[i], bp[i]); c != 0 {
				return c
			}
		}
	}
	return sign(len(ap) - len(bp))
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
