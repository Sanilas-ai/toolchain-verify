package reposcan

// Deliberately broken fixtures (scan-tuning-1117): large monorepos ship
// invalid package.json files under test/fixtures to test their own error
// paths; those must not turn the whole scan INCOMPLETE.

import (
	"strings"
	"testing"
)

func TestBrokenFixturesAreNotIncomplete(t *testing.T) {
	root := t.TempDir()
	write(t, root, "test/fixtures/packages/unparseable/package.json", "{\n  \"name\": \"x\"\n  \"version\": \"1.0.0\"\n}\n")
	write(t, root, "pkg/analyzer/testdata/wrong-packagejson/package.json", "{\"name\": \"x\",\n")
	write(t, root, "tests/specs/add/lockfile_only/package.json", "")                  // empty
	write(t, root, "tests/registry/lossy/package.json", "{\"name\": \"\xff\xfe\"}\n") // invalid UTF-8
	write(t, root, "package.json", "{\"name\": \"root\", \"scripts\": {\"test\": \"node t.js\"}}\n")
	rep := scan(t, root, Options{})
	if rep.Verdict != VerdictPass || len(rep.Coverage.Incomplete) != 0 {
		t.Fatalf("verdict %s %v%s", rep.Verdict, rep.Coverage.Incomplete, dump(rep))
	}
	if len(rep.Coverage.UnparsedFixtures) != 3 {
		t.Errorf("unparsed fixtures: %v", rep.Coverage.UnparsedFixtures)
	}
	f := mustFind(t, rep, "config.parse-error", "test/fixtures/packages/unparseable/package.json", SevInfo)
	if !strings.Contains(f.Message, "fixture") {
		t.Errorf("message: %s", f.Message)
	}
	mustFind(t, rep, "encoding.invalid-utf8", "tests/registry/lossy/package.json", SevInfo)
	if f := find(rep, "config.parse-error", "tests/specs/add/lockfile_only/package.json"); f != nil {
		t.Errorf("empty package.json flagged: %+v", f)
	}

	// Strict coverage keeps the honest INCOMPLETE.
	strict := scan(t, root, Options{StrictImages: true})
	if strict.Verdict != VerdictIncomplete {
		t.Errorf("strict: %s", strict.Verdict)
	}

	// Outside fixture trees a broken control file still blocks PASS.
	prod := t.TempDir()
	write(t, prod, "packages/app/package.json", "{\"name\": \"x\",\n")
	write(t, prod, ".mcp.json", "{")
	prep := scan(t, prod, Options{})
	if prep.Verdict != VerdictIncomplete || len(prep.Coverage.Incomplete) != 2 {
		t.Errorf("non-fixture: %s %v", prep.Verdict, prep.Coverage.Incomplete)
	}
	mustFind(t, prep, "config.parse-error", "packages/app/package.json", SevWarn)
}
