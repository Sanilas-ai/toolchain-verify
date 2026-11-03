package execpolicy

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func argvs(t *testing.T, s string) [][]string {
	t.Helper()
	cmds, err := SplitShell(s)
	if err != nil {
		t.Fatalf("SplitShell(%q): %v", s, err)
	}
	var out [][]string
	for _, c := range cmds {
		out = append(out, c.Argv)
	}
	return out
}

func TestSplitShell(t *testing.T) {
	cases := []struct {
		in   string
		want [][]string
	}{
		{"go test ./...", [][]string{{"go", "test", "./..."}}},
		{`git commit -m "a; b && c" && go vet`, [][]string{{"git", "commit", "-m", "a; b && c"}, {"go", "vet"}}},
		{`echo 'it''s' "x\"y" a\ b`, [][]string{{"echo", "its", `x"y`, "a b"}}},
		{"a | b |& c; d & e || f", [][]string{{"a"}, {"b"}, {"c"}, {"d"}, {"e"}, {"f"}}},
		{"FOO=1 BAR='x y' make -j4", [][]string{{"make", "-j4"}}},
		{"cd x && (npm ci; npm test)", [][]string{{"cd", "x"}, {"npm", "ci"}, {"npm", "test"}}},
		{"{ cargo build; }", [][]string{{"cargo", "build"}}},
		{"echo $(go version) `node -v`", [][]string{{"go", "version"}, {"node", "-v"}, {"echo", "$(go version)", "`node -v`"}}},
		{`echo "v=$(pnpm -v)"`, [][]string{{"pnpm", "-v"}, {"echo", "v=$(pnpm -v)"}}},
		{"echo $((1+2))", [][]string{{"echo", "$((1+2))"}}},
		{"diff <(go env) >(cat)", [][]string{{"go", "env"}, {"cat"}, {"diff", "<(go env)", ">(cat)"}}},
		{"ls > out.txt 2>&1 < in", [][]string{{"ls"}}},
		{"if true; then cargo test; fi", [][]string{{"true"}, {"cargo", "test"}}},
		{"for f in a b; do go run $f; done", [][]string{{"go", "run", "$f"}}},
		{"while read l; do echo $l; done < x", [][]string{{"read", "l"}, {"echo", "$l"}}},
		{"git status # && go build", [][]string{{"git", "status"}}},
		{"git status\nnpm ci", [][]string{{"git", "status"}, {"npm", "ci"}}},
		{"echo a\\\nb", [][]string{{"echo", "ab"}}},
		{"cat <<'EOF'\n$(go build)\nEOF\nls", [][]string{{"cat"}, {"ls"}}},
		{"cat <<EOF\n$(go build)\nEOF", [][]string{{"cat"}, {"go", "build"}}},
		{"bash <<EOF\nnpm ci\nEOF", [][]string{{"bash"}, {"npm", "ci"}}},
		{"cat <<-X | sh\n\tcargo test\n\tX", [][]string{{"cat"}, {"sh"}, {"cargo", "test"}}},
	}
	for _, c := range cases {
		if got := argvs(t, c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("SplitShell(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestSplitShellPipes(t *testing.T) {
	cmds, err := SplitShell("curl -fsSL https://x | sudo bash -s -- -y && ls")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 3 || !cmds[1].Piped || cmds[1].PipedFrom[0] != "curl" || cmds[2].Piped || cmds[0].Piped {
		t.Errorf("pipes = %+v", cmds)
	}
	cmds, _ = SplitShell("echo $(go env GOPATH)")
	if !cmds[0].Nested || cmds[1].Nested {
		t.Errorf("nested = %+v", cmds)
	}
}

func TestSplitShellUnparsable(t *testing.T) {
	for _, s := range []string{`echo "abc`, "echo 'abc", "echo $(go build", "echo `ls", "cat <<EOF\nno end", strings.Repeat("$(", 12) + "ls" + strings.Repeat(")", 12)} {
		if _, err := SplitShell(s); !errors.Is(err, ErrUnparsable) {
			t.Errorf("SplitShell(%q) err = %v, want ErrUnparsable", s, err)
		}
	}
}
