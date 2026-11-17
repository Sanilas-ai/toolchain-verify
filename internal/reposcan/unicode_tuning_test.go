package reposcan

// Synthetic fixtures for the unicode.* tuning (scan-tuning-1117): legitimate
// RTL marks and word-break characters in docs, translations and fixture
// data are info at most; control files, workflows and code keep severity.

import (
	"strings"
	"testing"
)

func TestUnicodeDocsAndTranslations(t *testing.T) {
	root := t.TempDir()
	// Khmer catalog: ZWSP between Khmer words.
	write(t, root, "app/locale/km/LC_MESSAGES/django.po", "msgid \"Unknown\"\nmsgstr \"មិន\u200Bដឹង\"\n\nmsgid \"Any date\"\nmsgstr \"កាល\u200Bបរិច្ឆេទ\u200Bណា\u200Bមួយ\"\n")
	// Central Kurdish catalog: RLE before every translated string.
	write(t, root, "app/locale/ckb/LC_MESSAGES/django.po", "msgid \"%(num)d year\"\nmsgstr \"\u202B%(num)d ساڵ\"\n\nmsgid \"%(num)d month\"\nmsgstr \"\u202B%(num)d مانگ\"\n\nmsgid \"day\"\nmsgstr \"\u202Bڕۆژ\"\n")
	write(t, root, "i18n/README.fa.md", "# Project\n\n\u202B[Project](https://example.invalid) یک جایگزین است\u202C\n")
	write(t, root, "tests/fixtures/url/urltestdata.json", `[{"input": "http://example.com/`+"\u202E"+`/foo/`+"\u202D"+`/bar"}, {"input": "http://example.com/`+"\uFEFF\u200B"+`/foo"}]`+"\n")
	write(t, root, "docs/zwsp.md", strings.Repeat("word\u200Bbreak ", 10)+"\n")
	rep := scan(t, root, Options{})
	if f := find(rep, "unicode.zero-width", "app/locale/km/LC_MESSAGES/django.po"); f != nil {
		t.Errorf("Khmer word breaks flagged: %+v", f)
	}
	n := 0
	for _, f := range rep.Findings {
		if f.Rule == "unicode.bidi-control" && f.Path == "app/locale/ckb/LC_MESSAGES/django.po" {
			n++
			if f.Severity != SevInfo || !strings.Contains(f.Message, "on 3 lines") {
				t.Errorf("ckb: %+v", f)
			}
		}
	}
	if n != 1 {
		t.Errorf("ckb: want one aggregated finding, got %d", n)
	}
	mustFind(t, rep, "unicode.bidi-control", "i18n/README.fa.md", SevInfo)
	mustFind(t, rep, "unicode.bidi-control", "tests/fixtures/url/urltestdata.json", SevInfo)
	mustFind(t, rep, "unicode.zero-width", "tests/fixtures/url/urltestdata.json", SevInfo)
	mustFind(t, rep, "unicode.zero-width", "docs/zwsp.md", SevInfo) // 10 single ZWSPs in docs
	if rep.Verdict != VerdictPass {
		t.Errorf("verdict %s%s", rep.Verdict, dump(rep))
	}
}

func TestUnicodeStrictWhereItMatters(t *testing.T) {
	root := t.TempDir()
	trojan := "\treturn a == \"user\u202E \u2066// admin\u2069 \u2066\"\n"
	write(t, root, "src/check.go", "package x\n\nfunc ok(a string) bool {\n"+trojan+"}\nfunc ok2(a string) bool {\n"+trojan+"}\n")
	// Code under tests/ is still code.
	write(t, root, "tests/test_auth.py", "def test():\n    assert check(\"user\u202E admin\")\n")
	write(t, root, "AGENTS.md", "Build with make.\u202E hidden\n")
	write(t, root, "locale/de/AGENTS.md", "Baue mit make.\u2066 versteckt\u2069\n") // control file inside locale/
	write(t, root, ".github/workflows/ci.yml", "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"ok\u202E\"\n")
	write(t, root, "docs/smuggle.md", "pass\u200b\u200b\u200b\u200bword\n") // long run: not a word break
	write(t, root, "src/split.js", "const k = 'to\u200bk\u200be\u200bn\u200b'; const j = 'a\u200bb\u200bc\u200bd\u200b';\n")
	rep := scan(t, root, Options{})
	f := mustFind(t, rep, "unicode.bidi-control", "src/check.go", SevWarn)
	if !strings.Contains(f.Message, "on 2 lines") || f.Line != 4 {
		t.Errorf("check.go aggregation: %+v", f)
	}
	mustFind(t, rep, "unicode.bidi-control", "tests/test_auth.py", SevWarn)
	mustFind(t, rep, "unicode.bidi-control", "AGENTS.md", SevFail)
	mustFind(t, rep, "unicode.bidi-control", "locale/de/AGENTS.md", SevFail)
	mustFind(t, rep, "unicode.bidi-control", ".github/workflows/ci.yml", SevFail)
	mustFind(t, rep, "unicode.zero-width", "docs/smuggle.md", SevWarn)
	mustFind(t, rep, "unicode.zero-width", "src/split.js", SevWarn)
}

func TestNoSpaceScriptZWSP(t *testing.T) {
	if runs := scanRunes([]byte("ภาษา\u200Bไทย 日本\u200B語")); len(runs) != 0 {
		t.Fatalf("Thai/CJK word breaks: %+v", runs)
	}
	if runs := scanRunes([]byte("ภาษา\u200Babc")); len(runs) != 1 {
		t.Fatalf("ZWSP between Thai and Latin must still count: %+v", runs)
	}
}
