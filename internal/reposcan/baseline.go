package reposcan

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"
)

// Baseline is an approved inventory of control files. New or changed
// control files are reported; approving them means re-writing the baseline
// after review (explicit --write-baseline, never automatic).
type Baseline struct {
	Version  int           `json:"version"`
	Created  string        `json:"created"`
	Reviewer string        `json:"reviewer,omitempty"`
	Files    []ControlFile `json:"files"`
}

// LoadBaseline reads a baseline file.
func LoadBaseline(p string) (*Baseline, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var bl Baseline
	dec := json.NewDecoder(bytesReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&bl); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if bl.Version != 1 {
		return nil, fmt.Errorf("%s: unsupported baseline version %d", p, bl.Version)
	}
	return &bl, nil
}

// NewBaseline builds a baseline from a report.
func NewBaseline(rep *Report, reviewer string) *Baseline {
	files := append([]ControlFile(nil), rep.Inventory...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return &Baseline{Version: 1, Created: time.Now().UTC().Format(time.RFC3339), Reviewer: reviewer, Files: files}
}

func (s *scanner) compareBaseline() {
	old := map[string]ControlFile{}
	for _, f := range s.opt.Baseline.Files {
		old[f.Path] = f
	}
	cur := map[string]bool{}
	for _, f := range s.rep.Inventory {
		cur[f.Path] = true
		o, ok := old[f.Path]
		switch {
		case !ok:
			s.add(Finding{Rule: "control.new", Severity: SevWarn, Path: f.Path, Message: "new " + f.Kind + " file not in the approved baseline",
				Fix: "review it, then refresh the baseline with --write-baseline"})
		case o.SHA256 != f.SHA256 || o.Symlink != f.Symlink:
			s.add(Finding{Rule: "control.changed", Severity: SevWarn, Path: f.Path, Message: f.Kind + " file changed since the approved baseline",
				Fix: "diff and review it, then refresh the baseline"})
		}
	}
	for p, f := range old {
		if !cur[p] {
			s.add(Finding{Rule: "control.removed", Severity: SevInfo, Path: p, Message: f.Kind + " file from the baseline is gone"})
		}
	}
}
