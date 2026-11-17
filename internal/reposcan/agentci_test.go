package reposcan

// Synthetic fixtures for agent.recursive-clone and ci.agent-publish-token.
// Secrets are referenced by name only; nothing is executed.

import (
	"strings"
	"testing"
)

func TestRecursiveClone(t *testing.T) {
	root := t.TempDir()
	write(t, root, "AGENTS.md", "# Setup\n\nRun `git clone --recurse-submodules https://example.invalid/x.git` first.\n")
	write(t, root, "scripts/bootstrap.sh", "#!/bin/sh\nset -e\ngit -c core.symlinks=true clone --recursive \"$1\" work\ncd work && git submodule update --init --recursive\n")
	write(t, root, ".cursor/rules/deps.mdc", "Always run git submodule update --init --recursive after pulling.\n")
	write(t, root, "Makefile", "deps:\n\tgit clone --recurse-submodules=vendor https://example.invalid/v.git\n")
	write(t, root, ".github/workflows/ci.yml", "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n        with:\n          submodules: recursive\n")
	rep := scan(t, root, Options{})
	f := mustFind(t, rep, "agent.recursive-clone", "AGENTS.md", SevWarn)
	if f.Line != 3 || len(f.CWE) == 0 || f.CWE[0] != "CWE-829" {
		t.Errorf("AGENTS.md: %+v", f)
	}
	// Aggregated per file since scan-tuning-1117 (was one finding per match).
	n := 0
	for _, f := range rep.Findings {
		if f.Rule == "agent.recursive-clone" && f.Path == "scripts/bootstrap.sh" {
			n++
			if f.Line != 3 || !strings.Contains(f.Message, "2 recursive submodule clones (lines 3, 4)") || !strings.Contains(f.Message, "2.56.1") {
				t.Errorf("bootstrap.sh: %+v", f)
			}
		}
	}
	if n != 1 {
		t.Errorf("bootstrap.sh: want 1 aggregated, got %d\n%s", n, dump(rep))
	}
	mustFind(t, rep, "agent.recursive-clone", ".cursor/rules/deps.mdc", SevWarn)
	mustFind(t, rep, "agent.recursive-clone", "Makefile", SevWarn)
	mustFind(t, rep, "agent.recursive-clone", ".github/workflows/ci.yml", SevWarn)

	// Several recursive checkouts in one workflow: one finding.
	multi := t.TempDir()
	write(t, multi, ".github/workflows/build.yml", "on: push\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n        with:\n          submodules: recursive\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n        with:\n          submodules: recursive\n")
	mrep := scan(t, multi, Options{})
	cnt := 0
	for _, f := range mrep.Findings {
		if f.Rule == "agent.recursive-clone" {
			cnt++
			if !strings.Contains(f.Message, "2 actions/checkout steps") || !strings.Contains(f.Message, "older than 2.56.1") {
				t.Errorf("build.yml: %+v", f)
			}
		}
	}
	if cnt != 1 {
		t.Errorf("build.yml: want 1, got %d%s", cnt, dump(mrep))
	}

	benign := t.TempDir()
	write(t, benign, "AGENTS.md", "Clone with `git clone --no-recurse-submodules URL`, then `git submodule update --init vendor/lib`.\n")
	write(t, benign, "scripts/a.sh", "git clone --depth 1 \"$URL\"\n# do not use --recursive here\n")
	write(t, benign, "README.md", "git clone --recurse-submodules is documented upstream\n") // not an agent/script file
	write(t, benign, ".github/workflows/ci.yml", "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n        with:\n          submodules: true\n")
	if f := find(scan(t, benign, Options{}), "agent.recursive-clone", ""); f != nil {
		t.Errorf("benign twin flagged: %+v", f)
	}
}

func TestAgentPublishToken(t *testing.T) {
	root := t.TempDir()
	// Codex triages issues in the same job that can publish to npm.
	write(t, root, ".github/workflows/triage.yml", `on:
  issues:
    types: [opened]
permissions:
  contents: read
jobs:
  triage:
    runs-on: ubuntu-latest
    env:
      NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
      - uses: openai/codex-action@0123456789abcdef0123456789abcdef01234567
        with:
          prompt: triage this issue
`)
	// Claude Code via npx with an OIDC token (trusted publishing) in the same job.
	write(t, root, ".github/workflows/release.yml", `on: workflow_dispatch
jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: write
    steps:
      - run: npx -y @anthropic-ai/claude-code -p "write the changelog"
      - run: npm publish --provenance
`)
	// Workflow-level permissions apply to a job without its own block.
	write(t, root, ".github/workflows/agent.yml", `on: push
permissions: write-all
jobs:
  fix:
    runs-on: ubuntu-latest
    steps:
      - run: |
          pip install aider-chat
          aider --yes --message "fix lint"
`)
	rep := scan(t, root, Options{})
	f := mustFind(t, rep, "ci.agent-publish-token", ".github/workflows/triage.yml", SevFail)
	if len(f.CWE) != 2 || f.CWE[0] != "CWE-269" || f.CWE[1] != "CWE-522" {
		t.Errorf("cwe: %+v", f.CWE)
	}
	if find(rep, "ci.agent-publish-token", ".github/workflows/release.yml") == nil || find(rep, "ci.agent-publish-token", ".github/workflows/agent.yml") == nil {
		t.Fatalf("release/agent: %s", dump(rep))
	}

	benign := t.TempDir()
	// Agent job is read-only; publishing happens in a separate job.
	write(t, benign, ".github/workflows/split.yml", `on: workflow_dispatch
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@0123456789abcdef0123456789abcdef01234567
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
  publish:
    needs: review
    runs-on: ubuntu-latest
    environment: release
    permissions:
      id-token: write
    env:
      NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
    steps:
      - run: npm publish --provenance
`)
	if f := find(scan(t, benign, Options{}), "ci.agent-publish-token", ""); f != nil {
		t.Errorf("split jobs flagged: %+v", f)
	}
}

// Severity grading of ci.agent-publish-token (who can start the agent).
func TestAgentPublishTokenGrading(t *testing.T) {
	commentOn := `on:
  issue_comment:
    types: [created]
  issues:
    types: [opened]
`
	cases := []struct {
		name, wf, sev, msg string
	}{
		{"ungated-comment", commentOn + `jobs:
  agent:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - run: npx -y @openai/codex exec "answer the comment"
`, SevFail, "no author_association filter"},
		{"author-association-gate", commentOn + `jobs:
  agent:
    if: contains(fromJSON('["OWNER", "MEMBER", "COLLABORATOR"]'), github.event.comment.author_association)
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: anthropics/claude-code-action@0123456789abcdef0123456789abcdef01234567
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
`, SevWarn, "author_association"},
		{"builtin-check-only", commentOn + `jobs:
  claude:
    if: contains(github.event.comment.body, '@claude')
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: anthropics/claude-code-action@0123456789abcdef0123456789abcdef01234567
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
`, SevWarn, "protection only inside the action"},
		{"non-write-users-star", commentOn + `jobs:
  claude:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: anthropics/claude-code-action@0123456789abcdef0123456789abcdef01234567
        with:
          allowed_non_write_users: "*"
`, SevFail, "allowed_non_write_users"},
		{"gate-allows-none", commentOn + `jobs:
  agent:
    if: contains(fromJSON('["OWNER", "NONE"]'), github.event.comment.author_association)
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: claude -p "triage"
`, SevFail, "no author_association filter"},
		{"dispatch-oidc-only", `on: workflow_dispatch
jobs:
  changelog:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: openai/codex-action@0123456789abcdef0123456789abcdef01234567
`, SevInfo, "only trusted triggers"},
		{"schedule-contents-write", `on:
  schedule:
    - cron: "0 0 * * *"
jobs:
  fix:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - run: aider --yes --message "update deps"
`, SevWarn, "only trusted triggers"},
		{"tag-push-publish-secret", `on:
  push:
    tags: ["v*"]
jobs:
  release:
    runs-on: ubuntu-latest
    env:
      NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
    steps:
      - run: codex exec "write release notes"
`, SevWarn, "secrets.NPM_TOKEN"},
	}
	for _, c := range cases {
		root := t.TempDir()
		write(t, root, ".github/workflows/w.yml", c.wf)
		rep := scan(t, root, Options{})
		f := find(rep, "ci.agent-publish-token", ".github/workflows/w.yml")
		if f == nil {
			t.Errorf("%s: no finding%s", c.name, dump(rep))
			continue
		}
		if f.Severity != c.sev || !strings.Contains(f.Message, c.msg) {
			t.Errorf("%s: %s %q, want %s containing %q", c.name, f.Severity, f.Message, c.sev, c.msg)
		}
	}
}

// gha.unpinned-action: one finding per workflow file; first-party only is
// info; a third-party tag in a privileged job is a separate warn.
func TestUnpinnedAggregation(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".github/workflows/ci.yml", `on: [push, pull_request]
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - uses: github/codeql-action/init@v3
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: example-org/setup-tool@v2
      - uses: example-org/lint
`)
	write(t, root, ".github/workflows/first.yml", `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/cache@main
`)
	write(t, root, ".github/workflows/prt.yml", `on: pull_request_target
permissions:
  contents: read
  pull-requests: write
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@v5
      - uses: example-org/comment-action@v1
        with:
          token: ${{ secrets.EXAMPLE_BOT_TOKEN }}
`)
	rep := scan(t, root, Options{})
	count := func(path string) (n int, fs []Finding) {
		for _, f := range rep.Findings {
			if f.Rule == "gha.unpinned-action" && f.Path == path {
				n++
				fs = append(fs, f)
			}
		}
		return
	}
	if n, fs := count(".github/workflows/ci.yml"); n != 1 || fs[0].Severity != SevWarn ||
		!strings.Contains(fs[0].Message, "6 uses:") || !strings.Contains(fs[0].Message, "2 third-party") ||
		!strings.Contains(fs[0].Evidence, "example-org/setup-tool@v2") || fs[0].Line != 8 {
		t.Errorf("ci.yml: %d %+v", n, fs)
	}
	if n, fs := count(".github/workflows/first.yml"); n != 1 || fs[0].Severity != SevInfo {
		t.Errorf("first.yml: %d %+v", n, fs)
	}
	n, fs := count(".github/workflows/prt.yml")
	if n != 2 {
		t.Fatalf("prt.yml: want aggregated info + privileged warn, got %d %+v", n, fs)
	}
	var warned, info bool
	for _, f := range fs {
		if f.Severity == SevWarn && f.Evidence == "example-org/comment-action@v1" && strings.Contains(f.Message, "pull_request_target") {
			warned = true
		}
		if f.Severity == SevInfo && f.Evidence == "actions/labeler@v5" {
			info = true
		}
	}
	if !warned || !info {
		t.Errorf("prt.yml: %+v", fs)
	}
}

// ci.agent-untrusted-trigger: agent on an untrusted trigger with read-only
// rights and no publish secrets is info (separate rule id, so the
// ci.agent-publish-token silence for such jobs stays as before).
func TestAgentUntrustedTriggerReadOnly(t *testing.T) {
	commentOn := "on:\n  issue_comment:\n    types: [created]\n"
	root := t.TempDir()
	write(t, root, ".github/workflows/open.yml", commentOn+`jobs:
  agent:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: read
    steps:
      - run: npx -y @openai/codex exec "answer"
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
`)
	write(t, root, ".github/workflows/builtin.yml", commentOn+`jobs:
  claude:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: anthropics/claude-code-action@0123456789abcdef0123456789abcdef01234567
`)
	rep := scan(t, root, Options{})
	f := mustFind(t, rep, "ci.agent-untrusted-trigger", ".github/workflows/open.yml", SevInfo)
	if !strings.Contains(f.Message, "API key") || !strings.Contains(f.Fix, "author_association") {
		t.Errorf("open.yml: %+v", f)
	}
	f = mustFind(t, rep, "ci.agent-untrusted-trigger", ".github/workflows/builtin.yml", SevInfo)
	if !strings.Contains(f.Message, "protection only inside the action") {
		t.Errorf("builtin.yml: %+v", f)
	}
	if f := find(rep, "ci.agent-publish-token", ""); f != nil {
		t.Errorf("read-only job got ci.agent-publish-token: %+v", f)
	}

	quietRoot := t.TempDir()
	// Gated by author_association: no finding.
	write(t, quietRoot, ".github/workflows/gated.yml", commentOn+`jobs:
  agent:
    if: contains(fromJSON('["OWNER", "MEMBER", "COLLABORATOR"]'), github.event.comment.author_association)
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - run: claude -p "answer"
`)
	// Trusted trigger, read-only: no finding.
	write(t, quietRoot, ".github/workflows/dispatch.yml", `on: workflow_dispatch
permissions:
  contents: read
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - run: claude -p "summarize"
`)
	qrep := scan(t, quietRoot, Options{})
	if f := find(qrep, "ci.agent-untrusted-trigger", ""); f != nil {
		t.Errorf("gated/trusted flagged: %+v", f)
	}
}
