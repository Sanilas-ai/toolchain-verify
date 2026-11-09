package reposcan

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// isInvisible reports format characters that render as nothing (or reorder
// text) and can hide instructions from a human reviewer.
func isInvisible(r rune) bool {
	switch {
	case r >= 0xE0000 && r <= 0xE007F: // Unicode Tags
		return true
	case r >= 0x200B && r <= 0x200F, r >= 0x202A && r <= 0x202E, r >= 0x2060 && r <= 0x2064, r >= 0x2066 && r <= 0x2069:
		return true
	case r == 0xFEFF, r == 0x180E, r == 0x00AD, r == 0x034F, r == 0x115F, r == 0x1160, r == 0x3164, r == 0xFFA0:
		return true
	case r >= 0xFE00 && r <= 0xFE0F, r >= 0xE0100 && r <= 0xE01EF: // variation selectors
		return true
	}
	return false
}

func isBidi(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}

// isEmojiBase approximates "a code point that can take ZWJ / VS16 / tag
// modifiers" (pictographs, dingbats, skin tones, regional indicators).
func isEmojiBase(r rune) bool {
	return (r >= 0x1F000 && r <= 0x1FAFF) || (r >= 0x2600 && r <= 0x27BF) || (r >= 0x2190 && r <= 0x21FF) ||
		(r >= 0x2300 && r <= 0x23FF) || (r >= 0x2B00 && r <= 0x2BFF) || r == 0x00A9 || r == 0x00AE || r == 0x203C ||
		r == 0x2049 || r == 0x2122 || r == 0x2139 || (r >= 0x3030 && r <= 0x303D) || r == 0x3297 || r == 0x3299 ||
		r == 0x20E3 || (r >= '0' && r <= '9') || r == '#' || r == '*'
}

// isJoiningScript: scripts where ZWNJ/ZWJ/LRM/RLM are ordinary typography
// (Arabic, Hebrew, Persian, Indic, Sinhala, Khmer, ...).
func isJoiningScript(r rune) bool {
	return unicode.In(r, unicode.Arabic, unicode.Hebrew, unicode.Syriac, unicode.Thaana, unicode.Devanagari,
		unicode.Bengali, unicode.Gurmukhi, unicode.Gujarati, unicode.Oriya, unicode.Tamil, unicode.Telugu,
		unicode.Kannada, unicode.Malayalam, unicode.Sinhala, unicode.Khmer, unicode.Myanmar, unicode.Mongolian)
}

// hiddenRun is one stretch of suspicious invisible characters.
type hiddenRun struct {
	kind    string // tags, bidi, zero-width, variation-selector
	offset  int    // byte offset in the file
	line    int
	count   int
	decoded string // Unicode Tags decoded to ASCII (may be empty)
}

// scanRunes finds invisible characters that are not part of legitimate
// emoji, flag or script sequences. Legit: ZWJ between emoji, VS15/VS16
// after a base character, the subdivision-flag tag sequence
// U+1F3F4 TAG... U+E007F, a BOM at offset 0, ZWNJ/ZWJ/LRM/RLM next to RTL
// or Indic letters.
func scanRunes(b []byte) []hiddenRun {
	var out []hiddenRun
	line := 1
	var prev rune = -1
	var cur *hiddenRun
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
			cur = nil
		}
	}
	add := func(kind string, off int, r rune) {
		if cur != nil && cur.kind != kind {
			flush()
		}
		if cur == nil {
			cur = &hiddenRun{kind: kind, offset: off, line: line}
		}
		cur.count++
		if kind == "tags" && r >= 0xE0020 && r <= 0xE007E {
			cur.decoded += string(rune(r - 0xE0000))
		}
	}
	inFlag := false // inside U+1F3F4 tag sequence
	vsRun := 0
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		next := rune(-1)
		if i+size < len(b) {
			next, _ = utf8.DecodeRune(b[i+size:])
		}
		switch {
		case r >= 0xE0000 && r <= 0xE007F:
			if prev == 0x1F3F4 {
				inFlag = true
			}
			if inFlag {
				if r == 0xE007F {
					inFlag = false
				}
				// legit flag tags are lower-case letters/digits, max ~6
				if r == 0xE007F || (r >= 0xE0061 && r <= 0xE007A) || (r >= 0xE0030 && r <= 0xE0039) {
					break
				}
			}
			add("tags", i, r)
		case isBidi(r):
			add("bidi", i, r)
		case r == 0x200D || r == 0x200C:
			if (isEmojiBase(prev) || prev == 0xFE0F || (prev >= 0x1F3FB && prev <= 0x1F3FF)) && (isEmojiBase(next) || next == -1) {
				break
			}
			if isJoiningScript(prev) || isJoiningScript(next) {
				break
			}
			add("zero-width", i, r)
		case r == 0x200E || r == 0x200F:
			if isJoiningScript(prev) || isJoiningScript(next) || unicode.IsDigit(next) || unicode.IsPunct(next) {
				break
			}
			add("zero-width", i, r)
		case r == 0xFEFF:
			if i == 0 {
				break
			}
			add("zero-width", i, r)
		case r == 0x200B || (r >= 0x2060 && r <= 0x2064) || r == 0x180E || r == 0x034F || r == 0x115F || r == 0x1160 || r == 0x3164 || r == 0xFFA0:
			add("zero-width", i, r)
		case r >= 0xE0100 && r <= 0xE01EF:
			// Ideographic variation sequences use one supplement selector
			// after a CJK base; runs carry smuggled bytes.
			vsRun++
			if vsRun >= 2 || !unicode.Is(unicode.Han, prev) {
				add("variation-selector", i, r)
			}
		case r >= 0xFE00 && r <= 0xFE0F:
			vsRun++
			if vsRun >= 2 || prev == -1 || prev == '\n' || unicode.IsSpace(prev) {
				add("variation-selector", i, r)
			}
		default:
			flush()
		}
		if !(r >= 0xFE00 && r <= 0xFE0F) && !(r >= 0xE0100 && r <= 0xE01EF) {
			vsRun = 0
		}
		if r == '\n' {
			line++
		}
		prev = r
		i += size
	}
	flush()
	return out
}

// escapeEvidence renders s so that every invisible, control or non-ASCII
// format character is visible as \u{XXXX}; newlines become ⏎. The result is
// at most max runes and is redacted for secrets.
func escapeEvidence(s string, max int) string {
	var sb strings.Builder
	n := 0
	for _, r := range s {
		if n >= max {
			sb.WriteString("…")
			break
		}
		switch {
		case r == '\n':
			sb.WriteString("⏎")
		case r == '\t':
			sb.WriteString(" ")
		case isInvisible(r) || r < 0x20 || r == 0x7F || unicode.Is(unicode.Cf, r) || r == utf8.RuneError:
			fmt.Fprintf(&sb, "\\u{%X}", r)
		default:
			sb.WriteRune(r)
		}
		n++
	}
	return redact(sb.String())
}

// snippetAround returns about width bytes of b around off, on rune
// boundaries.
func snippetAround(b []byte, off, width int) string {
	start := off - width/3
	if start < 0 {
		start = 0
	}
	end := start + width
	if end > len(b) {
		end = len(b)
	}
	for start > 0 && !utf8.RuneStart(b[start]) {
		start--
	}
	for end < len(b) && !utf8.RuneStart(b[end]) {
		end++
	}
	return string(b[start:end])
}

func lineOf(b []byte, off int) int {
	if off > len(b) {
		off = len(b)
	}
	return strings.Count(string(b[:off]), "\n") + 1
}
