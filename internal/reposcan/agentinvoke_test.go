package reposcan

// Synthetic fixtures for agent invocation detection (ci.agent-publish-token).
// The false-positive shapes are simplified from real workflows seen in the
// November 2026 mass scan (image names, npm package names, Co-authored-by
// trailers, comments); no project code or secret value is copied.

import "testing"

func TestAgentInvocation(t *testing.T) {
	yes := map[string]string{
		`codex exec --full-auto "fix the build"`:                  "codex exec",
		`npx -y @openai/codex@latest exec "triage"`:               "codex exec",
		`NODE_OPTIONS=--max-old-space-size=4096 claude -p "hi"`:   "claude -p",
		`npx --yes @anthropic-ai/claude-code --print "summarize"`: "claude --print",
		"set -e\nbash -c 'gemini -p \"review\"'":                   "gemini -p",
		"pip install aider-chat\naider --yes --message \"lint\"":   "aider --yes",
		`python3 -m openhands.core.main -t "solve the issue"`:     "python -m openhands.core.main",
		`timeout 600 openhands --headless -t "$TASK"`:             "openhands --headless",
		`uvx --from openhands-ai openhands --headless`:            "openhands --headless",
		`goose run --text "x"`:                                    "goose run",
		`out=$(cursor-agent -p "plan")`:                           "cursor-agent -p",
		"echo start && \\\n  codex exec \\\n  --sandbox read-only": "codex exec",
	}
	for in, want := range yes {
		if got := agentInvocation(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
	no := []string{
		// image names and paths
		`docker buildx imagetools create -t ghcr.io/openhands/agent-server:latest "$SRC"`,
		`docker pull openhands/runtime:main`,
		// npm package names in a publish job
		`npm publish "dist/npm/codex-npm-${VERSION}.tgz" --tag latest --provenance`,
		`npm view @openai/codex versions --json`,
		`npm install -g @openai/codex@latest`,
		// trailers, comments, echo strings
		`git commit -m "update snapshot" -m "Co-authored-by: openhands <bot@example.invalid>"`,
		"# advances @openai/codex@latest as soon as it publishes\nls dist",
		`echo "Codex left the changelog unchanged."`,
		`echo "run claude -p yourself"`,
		// setup and inspection only
		`codex --version`,
		`claude mcp add fs -- npx -y server-filesystem`,
		`codex login --with-api-key`,
		`goose configure`,
		// heredoc body is data
		"cat > prompt.md <<'EOF'\ncodex exec everything\nEOF\nwc -l prompt.md",
		// names that merely contain an agent name
		`./scripts/claude-code-stats.sh`,
		`codex-release-tool build`,
	}
	for _, in := range no {
		if got := agentInvocation(in); got != "" {
			t.Errorf("%q: false positive %q", in, got)
		}
	}
}

func TestAgentPublishTokenMentionsAreNotRuns(t *testing.T) {
	root := t.TempDir()
	// Shape of an image build/publish workflow whose project is named after
	// an agent: image names and comments mention it, no agent runs.
	write(t, root, ".github/workflows/docker.yml", `on:
  push:
    branches: [main]
permissions:
  contents: read
  packages: write
jobs:
  consolidate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
      # electron-builder names the DMG OpenHands-Agent-Canvas-<ver>.dmg
      - run: |
          docker buildx imagetools create \
            -t ghcr.io/openhands/agent-server:latest \
            ghcr.io/openhands/agent-server:${{ github.sha }}
`)
	// Scheduled snapshot update with a bot PAT and a Co-authored-by trailer.
	write(t, root, ".github/workflows/update-snapshot.yml", `on:
  schedule:
    - cron: "0 3 * * 1"
  workflow_dispatch:
jobs:
  update-snapshot:
    runs-on: ubuntu-latest
    env:
      GH_TOKEN: ${{ secrets.EXAMPLE_BOT_PUBLISH_PAT }}
      IMAGE: openhands/agent-canvas:snapshot-update
    steps:
      - run: |
          python scripts/update_snapshot.py
          git commit -am "chore: update snapshot" \
            -m "Co-authored-by: openhands <bot@example.invalid>"
`)
	// npm trusted publishing of a package named after an agent.
	write(t, root, ".github/workflows/rust-release.yml", `on:
  push:
    tags: ["rust-v*.*.*"]
jobs:
  publish-npm:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - run: |
          # The root wrapper advances @openai/codex@latest as soon as it publishes.
          for f in dist/npm/codex-npm-*-"${VERSION}".tgz; do
            npm publish "$f" --provenance --access public
          done
          npm view @openai/codex versions --json
`)
	rep := scan(t, root, Options{})
	if f := find(rep, "ci.agent-publish-token", ""); f != nil {
		t.Fatalf("mention flagged as an agent run: %+v", f)
	}
}
