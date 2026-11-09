// Package toolcall parses, validates and gates tool calls from small local
// models that often keep generating after the first call.
package toolcall

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
)

//go:embed profiles/*.toml
var embeddedProfiles embed.FS

// Format identifiers.
const (
	FormatLFM3XML      = "lfm3_xml"
	FormatLFM2Pythonic = "lfm2_pythonic"
	FormatMiniCPM5XML  = "minicpm5_xml"
	FormatHermesJSON   = "hermes_json"
)

// Profile describes how one model family emits tool calls and which stop
// sequences the runtime should use.
type Profile struct {
	ID            string   `toml:"id" json:"id"`
	Description   string   `toml:"description" json:"description"`
	Format        string   `toml:"format" json:"format"`
	CallStart     string   `toml:"call_start" json:"call_start"`
	CallEnd       string   `toml:"call_end" json:"call_end"`
	StopSequences []string `toml:"stop_sequences" json:"stop_sequences"`
	EOSToken      string   `toml:"eos_token" json:"eos_token,omitempty"`
	Sources       []string `toml:"sources" json:"sources,omitempty"`
}

var (
	profileOnce sync.Once
	profiles    map[string]Profile
	profileErr  error
)

// BuiltinProfiles returns the embedded per-model profiles.
func BuiltinProfiles() (map[string]Profile, error) {
	profileOnce.Do(func() {
		profiles = map[string]Profile{}
		ents, err := embeddedProfiles.ReadDir("profiles")
		if err != nil {
			profileErr = err
			return
		}
		for _, e := range ents {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".toml") {
				continue
			}
			b, err := embeddedProfiles.ReadFile("profiles/" + e.Name())
			if err != nil {
				profileErr = err
				return
			}
			var p Profile
			if _, err := toml.Decode(string(b), &p); err != nil {
				profileErr = fmt.Errorf("%s: %w", e.Name(), err)
				return
			}
			if p.ID == "" {
				profileErr = fmt.Errorf("%s: missing id", e.Name())
				return
			}
			profiles[p.ID] = p
		}
	})
	return profiles, profileErr
}

// LoadProfile returns a builtin profile by id, or loads a TOML file when
// pathOrID looks like a path.
func LoadProfile(pathOrID string) (Profile, error) {
	if strings.Contains(pathOrID, "/") || strings.HasSuffix(pathOrID, ".toml") {
		b, err := os.ReadFile(pathOrID)
		if err != nil {
			return Profile{}, err
		}
		var p Profile
		if _, err := toml.Decode(string(b), &p); err != nil {
			return Profile{}, err
		}
		if p.ID == "" {
			return Profile{}, fmt.Errorf("profile %s: missing id", pathOrID)
		}
		return p, nil
	}
	m, err := BuiltinProfiles()
	if err != nil {
		return Profile{}, err
	}
	p, ok := m[pathOrID]
	if !ok {
		return Profile{}, fmt.Errorf("unknown profile %q (want one of: %s)", pathOrID, strings.Join(profileIDs(m), ", "))
	}
	return p, nil
}

func profileIDs(m map[string]Profile) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	return ids
}

// ToolSpec is one allowlisted tool the model may call.
type ToolSpec struct {
	Name        string `json:"name" toml:"name"`
	Description string `json:"description,omitempty" toml:"description"`
	// DescriptionSHA256 pins the description against MCP/tool rug-pulls.
	// When set, a mismatched live description is rejected.
	DescriptionSHA256 string                 `json:"description_sha256,omitempty" toml:"description_sha256"`
	Schema            map[string]interface{} `json:"parameters" toml:"parameters"` // JSON Schema object
	// Class selects the human-gate bucket. Empty = "safe".
	// Known: safe, network, secrets, wallet, file_write, file_delete, shell, eval.
	Class string `json:"class,omitempty" toml:"class"`
}

// HashDescription returns the SHA-256 hex of s (normalized: trim + LF).
func HashDescription(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.TrimSpace(s)
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Limits bound untrusted model output.
type Limits struct {
	MaxInputBytes   int // default 256 KiB
	MaxArgBytes     int // default 32 KiB per argument value
	MaxNesting      int // default 8
	MaxCallsInInput int // we only keep the first valid one; this caps scan work (default 16)
	MaxRetries      int // structured-error retry budget advertised to the caller (default 2)
}

// DefaultLimits returns conservative defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxInputBytes:   256 << 10,
		MaxArgBytes:     32 << 10,
		MaxNesting:      8,
		MaxCallsInInput: 16,
		MaxRetries:      2,
	}
}

// Options configure Parse.
type Options struct {
	Profile Profile
	Tools   []ToolSpec
	Limits  Limits
	// Approver is consulted for sensitive classes. Nil = DenyAll.
	Approver Approver
	// CheckExfil rejects string args that look like .env / secret dumps
	// being shipped into a tool (Log-To-Leak pattern).
	CheckExfil bool
}

// Normalize fills defaults.
func (o *Options) Normalize() {
	if o.Limits.MaxInputBytes == 0 {
		o.Limits = DefaultLimits()
	}
	if o.Approver == nil {
		o.Approver = DenyAll{}
	}
}

// PrettyJSON is a small helper used by CLI / tests.
func PrettyJSON(v interface{}) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
	return buf.String()
}
