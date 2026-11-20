package reposcan

import "testing"

// Synthetic fixtures only: no real stealer code, no real tokens.
func TestWorkflowThreatIntel(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".github/workflows/loot.yml", `on: push
jobs:
  audit:
    runs-on: ubuntu-latest
    env:
      WF_SECRETS: ${{ toJSON(secrets) }}
    steps:
      - run: |
          printenv > /tmp/e.txt
          echo "${{ secrets.NPM_TOKEN }}" | base64
          npx -y some-cli
          npm install -g left-pad
      - run: gh run delete "$GITHUB_RUN_ID"
`)
	rep := scan(t, root, Options{})
	wf := ".github/workflows/loot.yml"
	mustFind(t, rep, "gha.secrets-dump", wf, SevFail)
	mustFind(t, rep, "gha.log-tamper", wf, SevFail)
	mustFind(t, rep, "gha.secret-echo", wf, SevWarn)
	mustFind(t, rep, "gha.unpinned-npx", wf, SevWarn)

	agent := t.TempDir()
	write(t, agent, ".github/workflows/triage.yml", `on:
  issue_comment:
    types: [created]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/codex-action@0123456789abcdef0123456789abcdef01234567
        with:
          prompt: "Fix this: ${{ github.event.comment.body }}"
  ungated:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@0123456789abcdef0123456789abcdef01234567
`)
	rep = scan(t, agent, Options{})
	sev := map[string]bool{}
	for _, f := range rep.Findings {
		if f.Rule == "ci.agent-untrusted-prompt" {
			sev[f.Severity] = true
		}
	}
	if !sev[SevFail] || !sev[SevWarn] {
		t.Errorf("agent on untrusted trigger: want fail (tainted prompt) and warn (ungated)\n%s", dump(rep))
	}

	benign := t.TempDir()
	write(t, benign, ".github/workflows/ok.yml", `on:
  issue_comment:
    types: [created]
jobs:
  triage:
    if: contains(fromJSON('["OWNER","MEMBER"]'), github.event.comment.author_association)
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: openai/codex-action@0123456789abcdef0123456789abcdef01234567
        with:
          prompt-file: .github/prompts/triage.md
      - env:
          LINT_CFG: ${{ vars.LINT_CFG }}
        run: |
          npx --no-install eslint .
          npx prettier@3.3.3 --check .
          npm i -g pnpm@9.12.0
          echo "environment ready"
`)
	quiet(t, scan(t, benign, Options{}))
}

func TestPkgPinned(t *testing.T) {
	for pkg, want := range map[string]bool{"a@1.2.3": true, "@s/a@2.0.0": true, "@s/a": false, "a": false, "a@latest": false, "a@next": false} {
		if pkgPinned(pkg) != want {
			t.Errorf("pkgPinned(%q) = %v", pkg, !want)
		}
	}
}
