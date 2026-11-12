# Changelog

All notable changes to toolchain-verify are documented here.
Format inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project uses [SemVer](https://semver.org/).

## [Unreleased]

### Added
- `host vps` (also `--profile vps`; `host all` now means apt + net + vps): an audit
  profile for internet-facing servers. New rules: `host.ssh-hostkeys-template`,
  `host.sshd-effective` (first value wins across `Include` drop-ins such as
  `50-cloud-init.conf`, or `--sshd-t` output), `host.kernel-stale`,
  `host.no-auto-updates`, `host.firewall-off` (ufw, nftables, iptables-persistent),
  `host.ssh-exposed`, `host.no-bruteforce-protection`, `host.ntp-unsynced`
  (`--timedatectl`) and `host.git-cve-2026-111760` (`--git-version`, distro backports
  recognised from `changelog.Debian.gz`). Still read-only; no command is executed.
- `scan`: `agent.recursive-clone` (recursive submodule clones in agent instructions,
  scripts, Makefiles and workflows, including `actions/checkout` `submodules: recursive`)
  and `ci.agent-publish-token` (an AI coding agent in a job that can reach publish
  secrets or `id-token`/`contents`/`packages: write`).
- Findings of `host` and `scan` carry a `cwe` list in JSON; `-v` prints it.
- Docs: agent tool update cooldown (~48 h) guidance; MCP governance gateways
  (ContextForge, Lunar MCPX, Agent Governance Toolkit, MCP-Defender) in the DESIGN backlog.

## [0.1.4] — 2026-11-10

### Added
- `toolchain-verify toolcall`: a pure-Go parser that keeps the first complete
  valid tool call from small local models (LFM3, LFM2, MiniCPM5, Hermes
  profiles), with schema validation, an allowlist, description SHA-256 pins,
  and a tty gate for sensitive classes.
- Apache-2.0 NOTICE is now shipped in the release archives alongside LICENSE.

### Fixed
- `agent --pre-session` without trusted roots is no longer a silent PASS (fail-open).
  It now emits `policy.no-trusted-roots` (warn) and returns exit `4` (INCOMPLETE).
  Configure `--trusted` / `agent.trusted_roots` for a complete pre-session gate.
- `agent --trusted DIR` no longer walks every checkout under a wide trusted root by
  default. Instruction/MCP walks are scoped to the current git repository (or cwd).
  Pass `--scope=trusted-roots` to restore the previous full walk.
- `.vscode/settings.json` and similar editor settings files are flagged as
  `mcp.writable` only when they actually contain MCP-related keys (`mcp`,
  `mcpServers`, `chat.mcp.*`, `mcp.*`, …). An eslint-only settings file produces
  no finding.
- `check`: when a relative `path` glob does not match, the error now states that
  relative globs resolve against the manifest directory and shows the resolved
  pattern.
- `agent` lists each exec-capable surface (kind, path, why) as `policy.exec-surface`.
  `policy.require-container` is INFO when already running in a container, not WARN.
  `DetectContainer` ignores a bare `$container` environment variable.

### Docs
- Published the 2026-11 mass-scan aggregate report.

[0.1.4]: https://github.com/Sanilas-ai/toolchain-verify/releases/tag/v0.1.4

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
