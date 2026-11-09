package toolcall

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// HiddenHit is one stretch of suspicious invisible characters.
type HiddenHit struct {
	Kind    string // tags, bidi, zero-width, variation-selector
	Offset  int
	Count   int
	Decoded string
}

func isInvisible(r rune) bool {
	switch {
	case r >= 0xE0000 && r <= 0xE007F:
		return true
	case r >= 0x200B && r <= 0x200F, r >= 0x202A && r <= 0x202E, r >= 0x2060 && r <= 0x2064, r >= 0x2066 && r <= 0x2069:
		return true
	case r == 0xFEFF, r == 0x180E, r == 0x00AD, r == 0x034F, r == 0x115F, r == 0x1160, r == 0x3164, r == 0xFFA0:
		return true
	case r >= 0xFE00 && r <= 0xFE0F, r >= 0xE0100 && r <= 0xE01EF:
		return true
	}
	return false
}

func isBidi(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}

// ScanHidden finds Unicode Tags, bidi controls and zero-width characters.
// Logic mirrors internal/reposcan (kept local so toolcall stays self-contained
// for sandbox builds that only compile this package).
func ScanHidden(s string) []HiddenHit {
	b := []byte(s)
	var out []HiddenHit
	var cur *HiddenHit
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
			cur = nil
		}
	}
	add := func(kind string, off int, r rune) {
		if cur != nil && cur.Kind != kind {
			flush()
		}
		if cur == nil {
			cur = &HiddenHit{Kind: kind, Offset: off}
		}
		cur.Count++
		if kind == "tags" && r >= 0xE0020 && r <= 0xE007E {
			cur.Decoded += string(rune(r - 0xE0000))
		}
	}
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		switch {
		case r >= 0xE0000 && r <= 0xE007F:
			add("tags", i, r)
		case isBidi(r):
			add("bidi", i, r)
		case r == 0x200B || r == 0x200C || r == 0x200D || r == 0x200E || r == 0x200F ||
			(r >= 0x2060 && r <= 0x2064) || r == 0xFEFF || r == 0x180E || r == 0x034F ||
			r == 0x115F || r == 0x1160 || r == 0x3164 || r == 0xFFA0 || r == 0x00AD:
			add("zero-width", i, r)
		case r >= 0xFE00 && r <= 0xFE0F, r >= 0xE0100 && r <= 0xE01EF:
			add("variation-selector", i, r)
		default:
			flush()
		}
		i += size
	}
	flush()
	return out
}

// StripHidden removes invisible format characters. Visible text is kept.
func StripHidden(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if isInvisible(r) || unicode.Is(unicode.Cf, r) && r != '\n' && r != '\t' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func describeHidden(hits []HiddenHit) []string {
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		s := fmt.Sprintf("%s@%d x%d", h.Kind, h.Offset, h.Count)
		if h.Decoded != "" {
			s += " decoded=" + h.Decoded
		}
		out = append(out, s)
	}
	return out
}
