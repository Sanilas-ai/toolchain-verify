package reposcan

// Synthetic fixtures for agent.recursive-clone and ci.agent-publish-token.
// Secrets are referenced by name only; nothing is executed.

import "testing"

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
	n := 0
	for _, f := range rep.Findings {
		if f.Rule == "agent.recursive-clone" && f.Path == "scripts/bootstrap.sh" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("bootstrap.sh: want 2, got %d\n%s", n, dump(rep))
	}
	mustFind(t, rep, "agent.recursive-clone", ".cursor/rules/deps.mdc", SevWarn)
	mustFind(t, rep, "agent.recursive-clone", "Makefile", SevWarn)
	mustFind(t, rep, "agent.recursive-clone", ".github/workflows/ci.yml", SevWarn)

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
