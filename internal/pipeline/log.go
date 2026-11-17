package pipeline

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Record is one mediator decision. It holds the rule, the verdict and the
// tool name. It does not hold argument text or a tainted span.
type Record struct {
	Rule    string  `json:"rule"`
	Verdict string  `json:"verdict"`
	Tool    string  `json:"tool"`
	Subject Subject `json:"subject"`
	Source  string  `json:"source,omitempty"`
}

// Log is the append-only record the agent does not write.
type Log struct {
	path string
	repo string
}

// OpenLog refuses a path inside repo and a credential basename.
func OpenLog(path, repo string) (*Log, error) {
	if path == "" {
		return nil, errors.New("mediator log path is empty")
	}
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case "auth.json", "credentials.json", ".credentials.json", "hosts.yml", "id_rsa", "id_ed25519":
		return nil, errors.New("refusing to use a credential file as the mediator log")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if repo != "" {
		root, err := filepath.Abs(repo)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(abs))
		if err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
			return nil, errors.New("mediator log must sit outside the repository")
		}
	}
	return &Log{path: abs, repo: repo}, nil
}

// Append writes one line. The file is created if needed. A symlink at the
// final path is refused on platforms that can refuse it.
func (l *Log) Append(r Record) error {
	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return err
	}
	f, err := openAppend(l.path)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = f.Write(b)
	return err
}

// Read returns every well-formed line. A missing file is an empty log.
func Read(path string) ([]Record, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Record
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var r Record
		if json.Unmarshal([]byte(line), &r) != nil {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}
