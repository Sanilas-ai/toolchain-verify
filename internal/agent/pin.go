package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

// InstructionLockVersion is the on-disk schema of an instruction pin.
const InstructionLockVersion = 1

// InstructionLock pins the instruction files an agent will load from a
// working directory.
type InstructionLock struct {
	Version int                 `json:"version"`
	Files   []InstructionPinned `json:"files"`
}

// InstructionPinned is one file, path relative to the working directory.
type InstructionPinned struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// CollectInstructions hashes instruction files under the working directory.
// Credential targets are skipped and reported. The hash covers at most 2 MiB.
func CollectInstructions(p *Policy, opt Options) ([]InstructionPinned, []Finding, error) {
	r, err := resolve(p, opt)
	if err != nil {
		return nil, nil, err
	}
	pins, findingsOut := r.instructionPins()
	return pins, findingsOut, nil
}

func (r *resolved) instructionPins() ([]InstructionPinned, []Finding) {
	var findingsOut []Finding
	var pins []InstructionPinned
	st := &walkStats{}
	root := filepath.Clean(r.cwd)
	r.walk(root, r.scanDepth, r.credDirs, st, func(p string, d fs.DirEntry) error {
		if d.IsDir() {
			if d.Name() == "node_modules" || d.Name() == ".git" || d.Name() == ".venv" {
				return filepath.SkipDir
			}
			return nil
		}
		if !matchInstruction(p, r.instrPatterns) {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil || strings.HasPrefix(rel, "..") {
			return nil
		}
		sum, err := hashFile(p, 2<<20)
		if err != nil {
			findingsOut = append(findingsOut, Finding{Rule: "instr.drift", Severity: SevFail, Path: filepath.ToSlash(rel),
				Message: "instruction file could not be hashed"})
			return nil
		}
		pins = append(pins, InstructionPinned{Path: filepath.ToSlash(rel), SHA256: sum})
		return nil
	})
	sort.Slice(pins, func(i, j int) bool { return pins[i].Path < pins[j].Path })
	return pins, findingsOut
}

// WriteInstructionLock writes a pin file mode 0600.
func WriteInstructionLock(path string, files []InstructionPinned) error {
	lock := InstructionLock{Version: InstructionLockVersion, Files: files}
	b, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// LoadInstructionLock reads a pin file.
func LoadInstructionLock(path string) (*InstructionLock, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock InstructionLock
	if err := json.Unmarshal(b, &lock); err != nil {
		return nil, err
	}
	return &lock, nil
}

func checkInstructionLock(r *resolved, c *collector) {
	if r.instructionLock == "" {
		return
	}
	lock, err := LoadInstructionLock(r.instructionLock)
	if err != nil {
		c.add(Finding{Rule: "instr.drift", Severity: SevFail, Path: r.instructionLock,
			Message: "instruction lock could not be read"})
		return
	}
	pins, extra := r.instructionPins()
	for _, f := range extra {
		c.add(f)
	}
	have := map[string]string{}
	for _, p := range pins {
		have[p.Path] = p.SHA256
	}
	want := map[string]string{}
	for _, p := range lock.Files {
		want[p.Path] = p.SHA256
	}
	for path, sum := range want {
		got, ok := have[path]
		if !ok {
			c.add(Finding{Rule: "instr.drift", Severity: SevFail, Path: path, Message: "pinned instruction file is missing"})
			continue
		}
		if got != sum {
			c.add(Finding{Rule: "instr.drift", Severity: SevFail, Path: path, Message: "instruction file hash does not match the pin"})
		}
	}
	for path := range have {
		if _, ok := want[path]; !ok {
			c.add(Finding{Rule: "instr.drift", Severity: SevFail, Path: path, Message: "instruction file is not in the pin"})
		}
	}
}

func hashFile(path string, limit int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, limit)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func checkDBAge(r *resolved, c *collector, updated string) {
	if strings.TrimSpace(updated) == "" {
		return
	}
	f, ok := findings.StaleDatabase("advisories.toml", updated, r.now(), r.dbMaxAgeDays)
	if ok {
		c.add(f)
	}
}
