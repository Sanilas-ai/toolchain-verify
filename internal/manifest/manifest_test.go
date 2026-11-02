package manifest

import (
	"strings"
	"testing"
)

func TestParseValid(t *testing.T) {
	m, err := Parse([]byte(`
require_container = true

[[tool]]
name = "go"
version = ">=1.22"
version_args = ["version"]

[[tool]]
name = "python"
command = "python3"
version = "~3.10"
version_regex = 'Python (?P<version>\S+)'
sha256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
optional = true
`))
	if err != nil {
		t.Fatal(err)
	}
	if m.RequireContainer == nil || !*m.RequireContainer {
		t.Error("require_container not parsed")
	}
	if len(m.Tools) != 2 {
		t.Fatalf("got %d tools", len(m.Tools))
	}
	if m.Tools[0].Command != "go" || m.Tools[0].VersionArgs[0] != "version" {
		t.Errorf("go defaults wrong: %+v", m.Tools[0])
	}
	py := m.Tools[1]
	if py.Command != "python3" || py.VersionArgs[0] != "--version" || py.Regex == nil || !py.Optional {
		t.Errorf("python fields wrong: %+v", py)
	}
	if py.SHA256 != strings.ToLower("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855") {
		t.Errorf("sha256 not normalized: %s", py.SHA256)
	}
}

func TestParseErrors(t *testing.T) {
	tests := map[string]string{
		"no tools":     `require_container = false`,
		"unknown key":  "[[tool]]\nname = \"go\"\nsha265 = \"x\"",
		"missing name": "[[tool]]\nversion = \"1\"",
		"duplicate":    "[[tool]]\nname = \"go\"\n[[tool]]\nname = \"go\"",
		"bad version":  "[[tool]]\nname = \"go\"\nversion = \"latest\"",
		"bad regex":    "[[tool]]\nname = \"go\"\nversion_regex = \"(\"",
		"bad sha":      "[[tool]]\nname = \"go\"\nsha256 = \"abc\"",
		"bad toml":     "[[tool]\nname = ",
	}
	for name, doc := range tests {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestParseAgentSection(t *testing.T) {
	m, err := Parse([]byte(`
require_container = true

[agent]
trusted_roots = ["~/open-source-polygon"]
untrusted_instruction = "warn"
scan_depth = 3
ignore = ["mcp.remote", "instr.untrusted:/tmp/**"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if m.Agent == nil || m.Agent.TrustedRoots[0] != "~/open-source-polygon" || m.Agent.ScanDepth != 3 {
		t.Errorf("agent section not parsed: %+v", m.Agent)
	}
	if len(m.Tools) != 0 {
		t.Error("agent-only manifest should have no tools")
	}
	for name, doc := range map[string]string{
		"agent typo":       "[agent]\ntrusted_root = [\"x\"]\n",
		"agent bad enum":   "[agent]\nuntrusted_instruction = \"maybe\"\n",
		"agent bad depth":  "[agent]\nscan_depth = 99\n",
		"agent bad ignore": "[agent]\nignore = [\":x\"]\n",
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}
