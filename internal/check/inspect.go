package check

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/Sanilas-ai/toolchain-verify/internal/manifest"
	"github.com/Sanilas-ai/toolchain-verify/internal/version"
)

// Observed is what is actually installed for one tool, independent of the
// manifest's version/path/sha256 expectations. It is what `pin` records.
type Observed struct {
	Found    string          // path found on PATH / --root
	Resolved string          // Found with symlinks resolved (absolute)
	SHA256   string          // digest of Resolved
	Version  version.Version // parsed from the version probe
}

// NotFoundError reports that a tool's command could not be located.
type NotFoundError struct{ Err error }

func (e *NotFoundError) Error() string { return e.Err.Error() }
func (e *NotFoundError) Unwrap() error { return e.Err }

// Inspect locates t, hashes the resolved binary and runs its version probe,
// using the same lookup rules as Run (no relative/empty PATH entries, --root).
// Unlike Run it does not compare against the manifest's expectations.
func Inspect(t *manifest.Tool, opt Options) (*Observed, error) {
	if opt.Timeout == 0 {
		opt.Timeout = 10 * time.Second
	}
	found, err := locate(t.Command, opt)
	if err != nil {
		return nil, &NotFoundError{err}
	}
	o := &Observed{Found: found}
	resolved, err := filepath.EvalSymlinks(found)
	if err != nil {
		return nil, fmt.Errorf("resolve symlinks: %w", err)
	}
	if o.Resolved, err = filepath.Abs(resolved); err != nil {
		return nil, err
	}
	if o.SHA256, err = fileSHA256(o.Resolved); err != nil {
		return nil, fmt.Errorf("hash: %w", err)
	}
	out, probeErr := probe(found, t.VersionArgs, opt.Timeout)
	v, err := extractVersion(out, t)
	if err != nil {
		if probeErr != nil {
			return nil, fmt.Errorf("version probe `%s %s` failed: %v", t.Command, strings.Join(t.VersionArgs, " "), probeErr)
		}
		return nil, err
	}
	o.Version = v
	return o, nil
}
