package toolcall

import (
	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
	"github.com/Sanilas-ai/toolchain-verify/internal/reposcan"
)

// ScrubReport is the result of cleaning one untrusted tool result.
// Text is the copy with hidden Unicode removed. Rules names the injection
// verdicts; the original text is not stored.
type ScrubReport struct {
	SchemaVersion int      `json:"schema_version"`
	OK            bool     `json:"ok"`
	Rules         []string `json:"rules,omitempty"`
	Text          string   `json:"text"`
}

// Scrub strips hidden Unicode and runs the injection signals. A tool result
// is treated as text an agent will read. Exit-worthy problems are a failing
// injection verdict or any hidden Unicode in the original.
func Scrub(s string) ScrubReport {
	rep := ScrubReport{SchemaVersion: findings.SchemaVersion, OK: true, Text: StripHidden(s)}
	if len(ScanHidden(s)) > 0 {
		rep.Rules = append(rep.Rules, "hidden-unicode")
		rep.OK = false
	}
	rule, sev := reposcan.InjectionVerdict(rep.Text, true)
	if rule != "" && sev == findings.SevFail {
		rep.Rules = append(rep.Rules, rule)
		rep.OK = false
	}
	return rep
}
