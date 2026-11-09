# Changelog

All notable changes to toolchain-verify are documented here.
Format inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project uses [SemVer](https://semver.org/).

## [0.1.3] — 2026-11-09

### Fixed
- `unicode.tag-smuggling`: FAIL only in agent-control files or when the decoded
  Tag payload carries instruction signals. Test/WPT/fixture paths without
  signals are demoted to info (Deno WPT hostname fixtures were a mass-scan FP).

[0.1.3]: https://github.com/Sanilas-ai/toolchain-verify/releases/tag/v0.1.3

## [0.1.2] — 2026-11-09

### Fixed
- `skill.secret-exfil`: require a strong credential path or named token env var.
  Bare `process.env` / `os.environ` plus HTTP no longer fails — that pattern is
  normal for skill tools and was a mass-scan false positive.

[0.1.2]: https://github.com/Sanilas-ai/toolchain-verify/releases/tag/v0.1.2

## [0.1.1] — 2026-11-09

### Fixed
- GitHub Action: install the release binary at an absolute path so `working-directory` no longer breaks the run step.
- GitHub Action: skip SARIF upload when the report file is missing or empty.

[0.1.1]: https://github.com/Sanilas-ai/toolchain-verify/releases/tag/v0.1.1

## [0.1.0] — 2026-11-09

First public release.

### Added
- Core CLI: `check`, `init`, `pin` against a declarative `toolchain.toml`.
- Agent protection: `agent` / `protect` (planted instructions, stack advisories, MCP configs, quarantine, pre-session gate).
- `exec-lint` for LLM-adjacent code execution sinks; `docker` host hygiene; `host` apt/net audit; `policy` host-vs-sandbox gate.
- `models` read-only scanner for GGUF / safetensors / pickle-based artifacts and Ollama stores.
- `scan` read-only repository scanner for agent control files, hidden instructions, risky MCP/workflows/hooks, and known IOCs; SARIF / JSON / baseline diff; exit `4` = INCOMPLETE.
- `mcp-tools` offline lint of a saved `tools/list` (poisoning, rug-pull pins).
- Reproducible multi-platform binaries via GoReleaser (linux/darwin/windows × amd64/arm64, `CGO_ENABLED=0`, `-trimpath`).
- Composite GitHub Action at the repository root: one-line `uses: Sanilas-ai/toolchain-verify@v0.1.0` downloads the release binary, verifies `SHA256SUMS`, runs `scan` (or another command), optionally uploads SARIF.
- Release workflow with SHA-pinned actions, SPDX SBOM (Syft), and build provenance attestation (GitHub OIDC).

### Security
- GitHub Actions in this repository are pinned to full commit SHAs.
- Scan treats third-party repos as hostile data: no symlink follow, size/depth/time limits, no execution of repository content.

[0.1.0]: https://github.com/Sanilas-ai/toolchain-verify/releases/tag/v0.1.0
