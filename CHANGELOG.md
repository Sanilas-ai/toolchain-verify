# Changelog

All notable changes to toolchain-verify are documented here.
Format inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project uses [SemVer](https://semver.org/).

## [Unreleased]

### Changed (scan tuning after the 2026-11-16 mass scan and manual review)
- `ci.agent-publish-token` fires only when the job actually runs an agent:
  `uses:` of a known agent action, or a shell command whose command word
  (after env/sudo/timeout/npx/uvx/pnpm dlx/pipx run/uv run/bash -c/
  python -m) is an agent CLI. Image names, npm package names in publish
  steps, Co-authored-by trailers, comments, echo strings, heredoc bodies and
  setup-only calls (`--version`, `login`, `mcp`) no longer count.
- `ci.agent-publish-token` is graded: **fail** for an untrusted trigger
  (issue_comment, issues, pull_request_target, pull_request_review*,
  discussion*, workflow_run) without an author_association/actor filter and
  without a built-in write check, or `allowed_non_write_users: "*"`;
  **warn** when gated to OWNER/MEMBER/COLLABORATOR, when the only protection
  is inside the action (claude-code-action write-permission check), or for
  other triggers with publish secrets / contents|packages write; **info**
  for trusted triggers only (dispatch, schedule, push, release) with just
  `id-token: write` and read-only contents.
- `gha.unpinned-action`: one finding per workflow file (count, actions in
  evidence); warn if a third-party action is unpinned, info if only
  `actions/*` / `github/*`. A third-party tag in a job with secrets or a
  write token under an untrusted trigger stays a separate warn.
- `unicode.bidi-control`: one finding per file; docs, translation catalogs
  (`.po`/`.mo`/`.xliff`, `locale/`, `i18n/`, `translations/`) and test
  fixture data are info. `unicode.zero-width`: info there unless a run of
  4+; ZWSP word breaks in Khmer/Thai/Lao/Myanmar/Tibetan/CJK are not
  counted. Control files, workflows and code keep their severity.
- `agent.recursive-clone`: one finding per file; the message states that
  the risk is real only where git is older than 2.56.1.
- Broken structured files inside test/fixture trees (invalid package.json
  fixtures in node, bun, deno, eslint, trivy) are info and listed in
  `coverage.unparsed_fixtures` instead of making the scan INCOMPLETE;
  `--strict-coverage` keeps them INCOMPLETE. Empty package.json/JSON configs
  are skipped.
- New `ci.agent-untrusted-trigger` (info): an agent really runs on an
  untrusted trigger with read-only permissions and no publish secrets and
  without an author_association/actor filter; prompt injection can still
  steer its output/comments and spend the API key.
- `snapshots/`, `__snapshots__/` and `*.snap` (insta, jest) count as test
  data for `unicode.*` and `coverage.unparsed_fixtures`.

### Added
- Threat-intel rules, November 2026 ([docs/threat-intel-2026-11.md](docs/threat-intel-2026-11.md)):
  - `host apps` (opt-in group, also in `host all`): `host.vscode-cve-2026-120779` (VS Code
    < 1.145.3), `host.llama-server-stale` (llama.cpp < b12340 via `--llama-version`),
    `host.ide-extension-denylist` (built-in: trojanized `anthropic.claude-code` 2.1.312 and
    2.1.313; extend with `[host.apps] extension_denylist`), `host.ssh-ioc-key`.
  - `host --authorized-keys-baseline FILE`: `host.authorized-keys-baseline` fails every
    authorized key that is not in the baseline. Keys are never printed.
  - `agent`: GPUStack advisories (CVE-2026-102895 in KEV, CVE-2026-102894); every
    version below 2.2.2 fails as critical. `mcp.remote-no-auth` warns on a remote MCP
    server with no client authentication (BluePhishing).
  - `scan`: `gha.secrets-dump` (`toJSON(secrets)`), `gha.log-tamper` (deleting runs or
    logs), `gha.secret-echo`, `gha.unpinned-npx` (wfx-loot, npm hijack) and
    `ci.agent-untrusted-prompt` (AI agent on issue/comment/fork-PR triggers).
  - `models`: `require_allow = true` makes a reviewed SHA-256 manifest mandatory
    (`models.not-allowlisted`).
- Threat-intel rules from the 2026-11-16 weekly plan:
  - `host secrets` (new group, on demand, not in `host all`): `host.secret-file` (HF,
    GitHub, AI-API, npm/PyPI tokens, exchange API keys, wallet seeds, git credentials in
    well-known files; kind + redacted prefix only), `host.secret-env` (names only) and
    `host.exchange-key-forbidden` (fail on hosts with `[host.secrets]
    forbid_exchange_keys = true` or `--sandbox-host`).
  - `host apps`: `host.chrome-cve-2026-125350` (Chrome/Chromium < 157.0.8103.50, KEV;
    `--chrome-version`), `host.php-cve-2026-109618` (PHP < 8.2.35/8.3.36/8.4.27/8.5.12 or
    EOL; `--php-version`), `host.path-user-writable` and `host.path-shadow` (`--path`),
    `host.version-manager-tamper` (pyenv/rbenv/nodenv dispatcher or shim, Homebrew links),
    `host.ide-extension-autoupdate`.
  - `agent`: blocklist entries for fake MCP packages `karma365-mcp` (npm), `dynamic-mcp`,
    `teamviewer-mcp-server`, `mcp-teamviewer` (PyPI); `mcp.blocklisted-package` matches MCP
    launch commands against the blocklist and the new `mcp_denylist`; `mcp.not-reviewed`
    enforces `mcp_reviewed` (exact reviewed specs).
- Agent write rules (`scan`) for agents with write/mutating tools, driven by an
  `agent-capabilities.toml`/`.json` manifest (new control-file kind, see
  [docs/design/agent-write-rules.md](docs/design/agent-write-rules.md)):
  - `agent.write-policy-code-derived`: the write admission policy must be derived from tool
    schemas (`write_policy.source = "schema"`);
  - `agent.write-plan-frozen-pre-untrusted`: the write plan is frozen before the first
    untrusted read (`write_plan.frozen_before_untrusted_read = true`, no
    `expand_after_untrusted`);
  - `agent.write-args-from-user`: sensitive write arguments (`role` recipient / content /
    amount / destination, or `sensitive = true`) need `source = "user"` or `human_confirm`.

  Manifest violations fail. Matching single-file code heuristics warn; they run on
  Python/JS/TS/Go files that call an LLM client. `agent.write-manifest` reports an
  unparsable manifest (warn, INCOMPLETE) or one with no write tools (info).
- Session trace (`trace`, `trace watch`) reads a Claude, Codex, or Cursor
  journal and fails on a shell call the exec policy rejects, a credential
  or out-of-root path, or an untrusted tool-result span that reappears in
  an outbound or write argument. The journal line is untrusted input: the
  verdict is the process exit code, not a second model.
- `posture` runs admission, pre-session, exec-policy validate, mcp-lock
  verify, and the advisory-database age check. The exit status is the worst
  of the five. Admission (`--agent-env`, `--agent-netns`) fails closed on a
  missing `none` network, a required container that this process is not in,
  a credential this uid can open, a hook or exec policy this uid can append,
  or a secret name in the supplied env file. `/proc/*/environ` is not read.
- `policy check --hook` is the action pipeline: mediator log
  (`--mediate-log`, outside `--repo`, rule, verdict, tool name, subject; no
  argument text), `--allow-subject`, a human `yes` on `/dev/tty` or
  `--approve` for a shell allow, `pipeline.path` / `pipeline.class` on
  arguments, and `claude-post` / `cursor-post` to scrub a tool result and
  remember an untrusted result as hashes keyed by `tool_use_id`
  (`pipeline.flow`). `policy check -c` without `--hook` does not ask on the
  terminal and does not write the log. `trace` stays the client journal.
- `toolcall scrub` strips hidden Unicode from a tool result and fails when
  an injection verdict remains. `scan --files -` scans only the paths on
  stdin. `policy check --follow-script` judges one script file inside the
  working directory. `agent --pin-instructions` / `--instructions-lock`
  hashes the instruction files an agent will load.
- Verifier fixes: negated or fenced `curl | sh` is info; an unexpanded
  argv[0] (including after sudo/env) is deny; `toolchain-verify:sandboxed`
  counts only on the call line next to a named wrapper, and a function that
  contains a sink is a dirty name; reports carry `schema_version` 1;
  a Docker port published on 0.0.0.0 or :: is `net.docker-bypass`; an
  advisory database older than `db_max_age_days` (default 45) is
  `policy.db-stale`; Windows opens refuse reparse points; a Claude or
  Cursor settings file without this binary is `agent.hook-missing` or
  `agent.hook-substituted`; world-readable session directories are
  `cred.transcript-perms`.
- Agent sandbox-isolation rules (`agent`): `agent.sandbox-approval-matrix`
  models the Codex `sandbox_mode` × `approval_policy` grid (danger-full-access
  + never = critical fail); `agent.no-isolation` flags Anthropic
  sandbox-runtime (`~/.srt-settings.json`) settings that weaken filesystem /
  network isolation, `--dangerously-*` bypass flags and Claude `sandbox:false`.
- MCP server isolation/secret rules: `mcp.no-isolation` warns on a stdio MCP
  server launched as a bare host process (no container / srt);
  `mcp.secrets-in-env` fails on a literal secret passed on the command line
  (world-visible via `ps`).
- `mcp-lock` subcommand: a lock file for MCP servers recording launch package,
  exact version and a sha256 integrity hash per server (mcpd-style). Verify
  catches version drift / package substitution (`mcp.lock`), unpinned
  `pkg@latest` (`mcp.lock-unpinned`) and new/removed servers; `--tools` folds
  tool-definition hashes to also flag rug-pulls.
- `host vps` (also `--profile vps`; `host all` now means apt + net + vps): an audit
  profile for internet-facing servers. New rules: `host.ssh-hostkeys-template`,
  `host.sshd-effective` (first value wins across `Include` drop-ins such as
  `50-cloud-init.conf`, or `--sshd-t` output), `host.kernel-stale`,
  `host.no-auto-updates`, `host.firewall-off` (ufw, nftables, iptables-persistent),
  `host.ssh-exposed`, `host.no-bruteforce-protection`, `host.ntp-unsynced`
  (`--timedatectl`) and `host.git-cve-2026-111760` (`--git-version`, distro backports
  recognised from `changelog.Debian.gz`). Still read-only; no command is executed.
- `host vps`: `host.sshd-effective` also fails on keyboard-interactive login with PAM
  (`KbdInteractiveAuthentication` / `ChallengeResponseAuthentication` yes + `UsePAM yes`).
  New rules `host.sudoers-nopasswd`, `host.authorized-keys-hygiene` and
  `host.listeners-policy` (allowlist via `[host.listen]` or `--listen-policy FILE`, or an
  info inventory). Docs: [fresh VPS checklist](docs/vps-fresh-image-checklist.md) with a
  note on vanilla WireGuard behind DPI.
- `scan`: `agent.recursive-clone` (recursive submodule clones in agent instructions,
  scripts, Makefiles and workflows, including `actions/checkout` `submodules: recursive`)
  and `ci.agent-publish-token` (an AI coding agent in a job that can reach publish
  secrets or `id-token`/`contents`/`packages: write`).
- Findings of `host` and `scan` carry a `cwe` list in JSON; `-v` prints it.
- Docs: `docs/agent-isolation.md` (rules + Codex sandbox×approval reference
  matrix + CWE mapping, and the action pipeline); `DESIGN.md` records the
  shipped hook pipeline, the trace, and the verifier fixes (TaskTracker
  probes and a NeMo Colang comparison stay research);
  agent tool update cooldown (~48 h) guidance; MCP governance gateways
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
