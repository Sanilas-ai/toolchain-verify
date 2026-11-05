package manifest

import (
	"strings"
	"testing"
)

const editDoc = `# header comment
require_container = false

[[tool]]
name = "go"   # the go toolchain
version = ">=1.22" # loose
version_args = [
  "version",
]
# sha256 = "commented out, must stay"

[[tool]]
  name = "git"
  command = "git"

  # trailing comment before next section

[agent]
trusted_roots = ["~/proj"]
notes = """
[[tool]]
name = "fake"
"""
`

func TestEditToolsReplaceAndInsert(t *testing.T) {
	out, err := EditTools([]byte(editDoc), []ToolEdit{
		{Index: 0, Set: map[string]string{"version": "1.27.3", "sha256": strings.Repeat("a", 64)}},
		{Index: 1, Set: map[string]string{"sha256": strings.Repeat("b", 64), "version": "2.43.0"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{
		"# header comment\n",
		`name = "go"   # the go toolchain` + "\n",
		`version = "1.27.3" # loose` + "\n",
		"  \"version\",\n]\nsha256 = \"" + strings.Repeat("a", 64) + "\"\n# sha256 = \"commented out, must stay\"\n",
		"  command = \"git\"\n  version = \"2.43.0\"\n  sha256 = \"" + strings.Repeat("b", 64) + "\"\n\n  # trailing comment before next section\n",
		"notes = \"\"\"\n[[tool]]\nname = \"fake\"\n\"\"\"\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// (EditTools itself re-decodes the result and verifies that only the
	// requested keys changed; the fake [[tool]] inside the string is data.)
}

func TestEditToolsNoChangesIsIdentity(t *testing.T) {
	out, err := EditTools([]byte(editDoc), nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != editDoc {
		t.Errorf("document changed:\n%s", out)
	}
}

func TestEditToolsCRLFAndEscaping(t *testing.T) {
	doc := "[[tool]]\r\nname = \"x\"\r\nversion = \"1\"\r\n"
	out, err := EditTools([]byte(doc), []ToolEdit{{Index: 0, Set: map[string]string{"version": "1.2.3", "path": `/opt/a "b"\c`}}})
	if err != nil {
		t.Fatal(err)
	}
	want := "[[tool]]\r\nname = \"x\"\r\nversion = \"1.2.3\"\r\npath = \"/opt/a \\\"b\\\"\\\\c\"\r\n"
	if string(out) != want {
		t.Errorf("got %q\nwant %q", out, want)
	}
	m, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if m.Tools[0].Path != `/opt/a "b"\c` {
		t.Errorf("path round-trip: %q", m.Tools[0].Path)
	}
}

func TestEditToolsErrors(t *testing.T) {
	cases := []struct {
		name, doc string
		edits     []ToolEdit
		want      string
	}{
		{"inline array", "tool = [{name = \"a\"}]\n", []ToolEdit{{Index: 0, Set: map[string]string{"version": "1"}}}, "only the [[tool]] table form"},
		{"index", "[[tool]]\nname = \"a\"\n", []ToolEdit{{Index: 3, Set: map[string]string{"version": "1"}}}, "out of range"},
		{"bad key", "[[tool]]\nname = \"a\"\n", []ToolEdit{{Index: 0, Set: map[string]string{"a.b": "1"}}}, "cannot edit key"},
		{"invalid toml", "[[tool]]\nname = \n", nil, ""},
		{"invalid utf8", "[[tool]]\nname = \"\xff\"\n", nil, "UTF-8"},
	}
	for _, c := range cases {
		_, err := EditTools([]byte(c.doc), c.edits)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want containing %q", c.name, err, c.want)
		}
	}
}

func TestEditToolsQuotedKey(t *testing.T) {
	// A quoted simple key ('version') is the same key as version.
	doc := "[[tool]]\nname = \"a\"\n'version' = \"1\"\n"
	out, err := EditTools([]byte(doc), []ToolEdit{{Index: 0, Set: map[string]string{"version": "2"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "'version' = \"2\"") {
		t.Errorf("quoted key not replaced:\n%s", out)
	}
}
