package toolcall

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// BenchCase is one transcript file outcome.
type BenchCase struct {
	File         string `json:"file"`
	Status       string `json:"status"`
	TrailingJunk bool   `json:"trailing_junk"`
	Name         string `json:"name,omitempty"`
	Error        string `json:"error,omitempty"`
}

// BenchReport aggregates parse/stop/valid rates over a directory.
type BenchReport struct {
	Dir           string      `json:"dir"`
	ProfileID     string      `json:"profile_id"`
	RuntimeNote   string      `json:"runtime_note,omitempty"`
	Total         int         `json:"total"`
	ParsedOK      int         `json:"parsed_ok"`
	TrailingJunk  int         `json:"trailing_junk"`
	StoppedClean  int         `json:"stopped_clean"` // parsed_ok && !trailing_junk
	SchemaFail    int         `json:"schema_fail"`
	Disallowed    int         `json:"disallowed"`
	OtherFail     int         `json:"other_fail"`
	ParseRate     float64     `json:"parse_rate"`
	StopCleanRate float64     `json:"stop_clean_rate"`
	ValidRate     float64     `json:"valid_rate"` // parsed_ok / total
	Cases         []BenchCase `json:"cases,omitempty"`
}

// BenchDir parses every regular file under dir (non-recursive by default;
// .jsonl lines count as one case each when the file ends with .jsonl).
func BenchDir(ctx context.Context, dir string, opt Options, recursive bool) (*BenchReport, error) {
	opt.Normalize()
	rep := &BenchReport{Dir: dir, ProfileID: opt.Profile.ID}
	var files []string
	walk := func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != dir && !recursive {
				return filepath.SkipDir
			}
			return nil
		}
		files = append(files, path)
		return nil
	}
	if err := filepath.WalkDir(dir, walk); err != nil {
		return nil, err
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			rep.Cases = append(rep.Cases, BenchCase{File: f, Status: "read_error", Error: err.Error()})
			rep.Total++
			rep.OtherFail++
			continue
		}
		texts := []string{string(b)}
		if strings.HasSuffix(f, ".jsonl") {
			texts = nil
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				var obj struct {
					Text   string `json:"text"`
					Output string `json:"output"`
				}
				if json.Unmarshal([]byte(line), &obj) == nil {
					t := obj.Text
					if t == "" {
						t = obj.Output
					}
					if t != "" {
						texts = append(texts, t)
						continue
					}
				}
				texts = append(texts, line)
			}
		}
		for i, text := range texts {
			label := f
			if len(texts) > 1 {
				label = fmt.Sprintf("%s:%d", f, i+1)
			}
			r := Parse(ctx, text, opt)
			rep.Total++
			bc := BenchCase{File: label, Status: r.Status, TrailingJunk: r.TrailingJunk}
			if r.Call != nil {
				bc.Name = r.Call.Name
			}
			if r.ModelError != nil {
				bc.Error = r.ModelError.Message
			}
			rep.Cases = append(rep.Cases, bc)
			switch r.Status {
			case StatusOK:
				rep.ParsedOK++
				if r.TrailingJunk {
					rep.TrailingJunk++
				} else {
					rep.StoppedClean++
				}
			case StatusSchema:
				rep.SchemaFail++
			case StatusDisallowed:
				rep.Disallowed++
			default:
				rep.OtherFail++
				if r.TrailingJunk {
					rep.TrailingJunk++
				}
			}
		}
	}
	if rep.Total > 0 {
		rep.ParseRate = float64(rep.ParsedOK) / float64(rep.Total)
		rep.ValidRate = rep.ParseRate
		rep.StopCleanRate = float64(rep.StoppedClean) / float64(rep.Total)
	}
	return rep, nil
}
