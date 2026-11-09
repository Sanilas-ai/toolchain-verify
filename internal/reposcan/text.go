package reposcan

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

const evidenceRunes = 160

// scanText runs the checks that apply to every text file: invisible
// characters, HTML-hidden instructions (markup files), IOC strings.
func (s *scanner) scanText(rel, kind string, b []byte) {
	control := kind != ""
	s.scanHiddenRunes(rel, control, b)
	if isMarkupName(path.Base(rel)) || kind == KindInstructions {
		s.scanHiddenMarkup(rel, control, b)
	}
	s.scanIOCText(rel, kind, b)
}

func (s *scanner) scanHiddenRunes(rel string, control bool, b []byte) {
	runs := scanRunes(b)
	if len(runs) == 0 {
		return
	}
	zw, zwMax := 0, 0
	var zwFirst *hiddenRun
	for i := range runs {
		r := runs[i]
		ev := escapeEvidence(snippetAround(b, r.offset, 120), evidenceRunes)
		switch r.kind {
		case "tags":
			f := Finding{Rule: "unicode.tag-smuggling", Severity: SevFail, Path: rel, Line: r.line, Offset: r.offset, Evidence: ev,
				Decoded: escapeEvidence(r.decoded, evidenceRunes),
				Message: fmt.Sprintf("%d invisible Unicode Tag characters (U+E0000–E007F) outside an emoji flag sequence; models read them as text, reviewers see nothing", r.count),
				Fix:     "remove the tag characters; review who added them (git log -p)",
				Refs:    []string{"https://aws.amazon.com/blogs/security/defending-llm-applications-against-unicode-character-smuggling/"}}
			if sig := signals(canonical(r.decoded)); len(sig) > 0 {
				f.Signals = sigList(sig)
				f.Message += "; decoded text carries instruction signals"
			}
			s.add(f)
		case "bidi":
			sev := SevWarn
			if control {
				sev = SevFail
			}
			s.add(Finding{Rule: "unicode.bidi-control", Severity: sev, Path: rel, Line: r.line, Offset: r.offset, Evidence: ev,
				Message: fmt.Sprintf("%d bidirectional override/isolate characters: displayed text differs from logical order (Trojan Source)", r.count),
				Fix:     "remove the bidi controls or justify them (RTL UI strings)",
				Refs:    []string{"https://trojansource.codes/"}})
		case "variation-selector":
			sev := SevInfo
			switch {
			case r.count >= 4:
				sev = SevFail
			case control:
				sev = SevWarn
			}
			s.add(Finding{Rule: "unicode.variation-selector", Severity: sev, Path: rel, Line: r.line, Offset: r.offset, Evidence: ev,
				Message: fmt.Sprintf("run of %d variation selectors not attached to an emoji/ideograph; long runs can smuggle bytes", r.count)})
		case "zero-width":
			zw += r.count
			if r.count > zwMax {
				zwMax = r.count
			}
			if zwFirst == nil {
				zwFirst = &runs[i]
			}
		}
	}
	if zw > 0 {
		sev := SevInfo
		switch {
		case control:
			sev = SevWarn
		case zw >= 8 || zwMax >= 4:
			sev = SevWarn
		}
		s.add(Finding{Rule: "unicode.zero-width", Severity: sev, Path: rel, Line: zwFirst.line, Offset: zwFirst.offset,
			Evidence: escapeEvidence(snippetAround(b, zwFirst.offset, 120), evidenceRunes),
			Message:  fmt.Sprintf("%d zero-width/invisible characters (longest run %d) outside emoji or RTL/Indic text", zw, zwMax),
			Fix:      "remove them; they split keywords past filters or encode hidden data"})
	}
}

var (
	htmlCommentRe = regexp.MustCompile(`(?s)<!--(.*?)-->`)
	mdCommentRe   = regexp.MustCompile(`(?m)^\[(?://|comment|_)\]:\s*#\s*[("'](.*)[)"']\s*$`)
	detailsRe     = regexp.MustCompile(`(?is)<details[^>]*>(.*?)</details>`)
	hiddenStyleRe = regexp.MustCompile(`(?is)<([a-z][a-z0-9]*)\b[^>]*\b(?:hidden\b|aria-hidden\s*=\s*["']true["']|style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|em|rem|pt)?\s*(?:;|["'])|opacity\s*:\s*0(?:\.0+)?\s*(?:;|["'])|color\s*:\s*(?:white|#fff\b|#ffffff|transparent)|height\s*:\s*0|width\s*:\s*0|position\s*:\s*absolute[^"']*left\s*:\s*-\d{3,}))[^>]*>(.*?)</([a-z][a-z0-9]*)>`)
	latexHiddenRe = regexp.MustCompile(`(?s)\\(?:textcolor|color)\{(?:white|#fff|#ffffff)\}\{([^}]{0,1000})\}|\\phantom\{([^}]{0,1000})\}`)
	entityRunRe   = regexp.MustCompile(`(?:&#(?:x[0-9a-fA-F]{2,6}|[0-9]{2,7});){6,}`)
)

// scanHiddenMarkup looks at text that a renderer hides (HTML comments,
// hidden elements, white LaTeX) or folds (<details>) and at entity-encoded
// runs. Hidden text is only reported when it carries instruction signals:
// plain comments (templates, lint markers) are common and benign.
func (s *scanner) scanHiddenMarkup(rel string, control bool, b []byte) {
	text := string(b)
	type chunk struct {
		how      string
		off      int
		body     string
		isHidden bool
	}
	var chunks []chunk
	for _, m := range htmlCommentRe.FindAllStringSubmatchIndex(text, -1) {
		chunks = append(chunks, chunk{"html-comment", m[0], text[m[2]:m[3]], true})
	}
	for _, m := range mdCommentRe.FindAllStringSubmatchIndex(text, -1) {
		chunks = append(chunks, chunk{"markdown-comment", m[0], text[m[2]:m[3]], true})
	}
	for _, m := range hiddenStyleRe.FindAllStringSubmatchIndex(text, -1) {
		chunks = append(chunks, chunk{"hidden-element", m[0], text[m[2*2]:m[2*2+1]], true})
	}
	for _, m := range latexHiddenRe.FindAllStringSubmatchIndex(text, -1) {
		body := ""
		if m[2] >= 0 {
			body = text[m[2]:m[3]]
		} else if m[4] >= 0 {
			body = text[m[4]:m[5]]
		}
		chunks = append(chunks, chunk{"latex-hidden", m[0], body, true})
	}
	for _, m := range detailsRe.FindAllStringSubmatchIndex(text, -1) {
		chunks = append(chunks, chunk{"details", m[0], text[m[2]:m[3]], false})
	}
	for _, c := range chunks {
		sig := signals(canonical(c.body))
		// Hidden text addressed to an agent is judged like a control file.
		rule, sev := verdictFor(sig, c.isHidden || control)
		if rule == "" {
			continue
		}
		if c.isHidden {
			rule = "hidden." + strings.TrimPrefix(rule, "injection.")
			if sev == SevWarn && (sig[sigOverride] || sig[sigForgedRole] || sig[sigConceal]) {
				sev = SevFail // a hidden "ignore previous instructions" has no benign reading
			}
		}
		s.add(Finding{Rule: rule, Severity: sev, Path: rel, Line: lineOf(b, c.off), Offset: c.off,
			Evidence: escapeEvidence(c.body, evidenceRunes), Signals: sigList(sig),
			Message: fmt.Sprintf("%s contains agent-directed instructions that a human reader does not see rendered", c.how),
			Fix:     "remove the hidden block; treat the file as untrusted input until reviewed",
			Refs:    []string{"https://www.radware.com/blog/prompt-injecting-coding-agents/"}})
	}
	for _, m := range entityRunRe.FindAllStringIndex(text, -1) {
		dec := canonical(text[m[0]:m[1]])
		sig := signals(dec)
		sev := SevInfo
		if len(sig) > 0 || control {
			sev = SevWarn
		}
		if r, _ := verdictFor(sig, true); r != "" {
			sev = SevFail
		}
		s.add(Finding{Rule: "encoding.html-entities", Severity: sev, Path: rel, Line: lineOf(b, m[0]), Offset: m[0],
			Evidence: escapeEvidence(text[m[0]:m[1]], 80), Decoded: escapeEvidence(dec, evidenceRunes), Signals: sigList(sig),
			Message: "long run of numeric HTML entities spelling plain text (filter evasion by encoding)"})
	}
}

// chunkText splits text into paragraphs (blank-line separated; fenced code
// blocks stay whole) with their byte offsets. Correlation of signals is
// done per paragraph so that unrelated sections of a long instruction file
// are not combined into a false "secret→network" chain.
func chunkText(b []byte) (offs []int, parts []string) {
	text := string(b)
	start := 0
	inFence := false
	lineStart := 0
	flush := func(end int) {
		if strings.TrimSpace(text[start:end]) != "" {
			offs = append(offs, start)
			parts = append(parts, text[start:end])
		}
	}
	for lineStart <= len(text) {
		nl := strings.IndexByte(text[lineStart:], '\n')
		lineEnd := len(text)
		if nl >= 0 {
			lineEnd = lineStart + nl
		}
		line := strings.TrimSpace(text[lineStart:lineEnd])
		if strings.HasPrefix(line, "```") || strings.HasPrefix(line, "~~~") {
			inFence = !inFence
		}
		if line == "" && !inFence {
			flush(lineStart)
			start = min(lineEnd+1, len(text))
		}
		if nl < 0 {
			break
		}
		lineStart = lineEnd + 1
	}
	flush(len(text))
	return
}

// scanTextControl judges text that an agent loads as instructions.
func (s *scanner) scanTextControl(rel, kind string, b []byte) {
	offs, parts := chunkText(b)
	for i, part := range parts {
		sig := signals(canonical(part))
		rule, sev := verdictFor(sig, true)
		if rule == "" {
			continue
		}
		s.add(Finding{Rule: rule, Severity: sev, Path: rel, Line: lineOf(b, offs[i]), Offset: offs[i],
			Evidence: escapeEvidence(strings.TrimSpace(part), evidenceRunes), Signals: sigList(sig),
			Message: fmt.Sprintf("%s file asks the agent to do something risky (%s)", kind, strings.Join(sigList(sig), ", ")),
			Fix:     "review the paragraph; agent instructions must not install, fetch, touch credentials, rewrite agent config or skip approvals",
			Refs:    []string{"https://forever.security/blog/hijacking-ai-agents-via-downloads-folder/"}})
	}
}
