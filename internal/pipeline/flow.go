package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// grams are the phrases a later call must not repeat. Short instructions
// count: a pair of words is enough once the joined form is at least 8 bytes.
func grams(s string) []string {
	fields := strings.Fields(s)
	var out []string
	seen := map[string]bool{}
	add := func(g string) {
		if len(g) < 8 || len(g) > 200 || seen[g] {
			return
		}
		seen[g] = true
		out = append(out, g)
	}
	for i := range fields {
		for n := 1; n <= 3 && i+n <= len(fields); n++ {
			add(strings.Join(fields[i:i+n], " "))
			if len(out) >= 64 {
				return out
			}
		}
	}
	return out
}

func hashGram(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

type flowItem struct {
	ID     string   `json:"id"`
	Hashes []string `json:"hashes"`
}

type flowState struct {
	Items []flowItem `json:"items"`
}

// Remember stores hashes of an untrusted tool result under its tool_use id.
// The result text is not written.
func Remember(path, id, text string) error {
	if path == "" || strings.TrimSpace(text) == "" {
		return nil
	}
	gs := grams(text)
	if len(gs) == 0 {
		return nil
	}
	hashes := make([]string, len(gs))
	for i, g := range gs {
		hashes[i] = hashGram(g)
	}
	st := loadFlow(path)
	st.Items = append(st.Items, flowItem{ID: id, Hashes: hashes})
	if len(st.Items) > 32 {
		st.Items = st.Items[len(st.Items)-32:]
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return writeNoFollow(path, append(b, '\n'))
}

// Flow reports whether args repeat a remembered untrusted result.
// The source tool_use id is returned. Argument text is not.
func Flow(path, args string) (string, bool) {
	if path == "" {
		return "", false
	}
	st := loadFlow(path)
	if len(st.Items) == 0 {
		return "", false
	}
	want := map[string]string{}
	for _, it := range st.Items {
		for _, h := range it.Hashes {
			if _, ok := want[h]; !ok {
				want[h] = it.ID
			}
		}
	}
	for _, g := range grams(args) {
		if id, ok := want[hashGram(g)]; ok {
			return id, true
		}
	}
	return "", false
}

func loadFlow(path string) flowState {
	b, err := os.ReadFile(path)
	if err != nil {
		return flowState{}
	}
	var st flowState
	if json.Unmarshal(b, &st) != nil {
		return flowState{}
	}
	return st
}
