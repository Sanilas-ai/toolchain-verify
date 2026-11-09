package toolcall

import (
	"fmt"
	"net/url"
	"strings"
)

// Obsessive refusal string (exact) from the Obsessive-1.7B grounded pattern.
const NotFoundInSearchResults = "Not found in the search results"

// GroundedAnswer is the structured search-subagent output.
type GroundedAnswer struct {
	Answer   string `json:"answer,omitempty"`
	Quote    string `json:"quote,omitempty"`
	URL      string `json:"url,omitempty"`
	NotFound bool   `json:"not_found"`
	Raw      string `json:"raw,omitempty"`
}

// GroundedResult is the validator outcome.
type GroundedResult struct {
	OK            bool           `json:"ok"`
	Answer        GroundedAnswer `json:"answer"`
	QuoteVerified bool           `json:"quote_verified,omitempty"`
	Error         string         `json:"error,omitempty"`
}

// ParseGrounded parses the Obsessive-style grounded format:
//
//	answer: ...
//	quote: ...
//	url: https://...
//
// or the literal refusal line "Not found in the search results".
// Field labels are case-insensitive; order is answer → quote → url.
func ParseGrounded(text string) (GroundedAnswer, error) {
	s := strings.TrimSpace(StripHidden(text))
	if s == NotFoundInSearchResults {
		return GroundedAnswer{NotFound: true, Raw: s}, nil
	}
	// also accept a leading label form
	lines := splitKeep(s)
	ga := GroundedAnswer{Raw: s}
	var cur string
	var buf strings.Builder
	flush := func() {
		v := strings.TrimSpace(buf.String())
		switch cur {
		case "answer":
			ga.Answer = v
		case "quote":
			ga.Quote = v
		case "url":
			ga.URL = v
		}
		buf.Reset()
	}
	for _, line := range lines {
		low := strings.ToLower(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(low, "answer:"):
			flush()
			cur = "answer"
			buf.WriteString(strings.TrimSpace(line[len("answer:"):]))
		case strings.HasPrefix(low, "quote:"):
			flush()
			cur = "quote"
			buf.WriteString(strings.TrimSpace(line[len("quote:"):]))
		case strings.HasPrefix(low, "url:"):
			flush()
			cur = "url"
			buf.WriteString(strings.TrimSpace(line[len("url:"):]))
		case strings.HasPrefix(low, "verbatim quote:"):
			flush()
			cur = "quote"
			buf.WriteString(strings.TrimSpace(line[len("verbatim quote:"):]))
		case strings.HasPrefix(low, "source url:"):
			flush()
			cur = "url"
			buf.WriteString(strings.TrimSpace(line[len("source url:"):]))
		default:
			if cur == "" {
				continue
			}
			if buf.Len() > 0 {
				buf.WriteByte('\n')
			}
			buf.WriteString(line)
		}
	}
	flush()
	if ga.Answer == "" && ga.Quote == "" && ga.URL == "" {
		return ga, fmt.Errorf("not a grounded answer (missing answer/quote/url) and not the exact refusal string")
	}
	return ga, nil
}

// ValidateGrounded checks structure and optionally that quote appears
// verbatim in sourceText.
func ValidateGrounded(text, sourceText string) GroundedResult {
	ga, err := ParseGrounded(text)
	if err != nil {
		return GroundedResult{OK: false, Error: err.Error()}
	}
	if ga.NotFound {
		return GroundedResult{OK: true, Answer: ga}
	}
	if strings.TrimSpace(ga.Answer) == "" {
		return GroundedResult{OK: false, Answer: ga, Error: "empty answer"}
	}
	if strings.TrimSpace(ga.Quote) == "" {
		return GroundedResult{OK: false, Answer: ga, Error: "empty verbatim quote"}
	}
	if strings.TrimSpace(ga.URL) == "" {
		return GroundedResult{OK: false, Answer: ga, Error: "empty source URL"}
	}
	u, err := url.Parse(ga.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return GroundedResult{OK: false, Answer: ga, Error: "source URL must be http(s) with a host"}
	}
	out := GroundedResult{OK: true, Answer: ga}
	if sourceText != "" {
		if strings.Contains(sourceText, ga.Quote) {
			out.QuoteVerified = true
		} else {
			out.OK = false
			out.QuoteVerified = false
			out.Error = "verbatim quote not found in supplied source text (possible hallucination)"
		}
	}
	return out
}

func splitKeep(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.Split(s, "\n")
}
