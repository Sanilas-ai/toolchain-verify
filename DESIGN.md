# Design and threat model

## Goal

Make "which toolchain did this build/test actually use?" an explicit, checkable
fact instead of an assumption. A manifest is committed next to the code; CI,
a Docker sandbox, or a developer runs `toolchain-verify check` before building.
Non-zero exit stops the pipeline.

## Threats addressed

| Threat | Example | Mitigation |
|---|---|---|
| **Wrong binary on PATH** | `~/.local/bin/node` shadows the system node; a planted `git` in a writable dir early in PATH; `.` or an empty entry in `PATH` | Report the found *and* symlink-resolved path; optional `path` glob; optional `sha256`; relative/empty `PATH` entries are never searched |
| **Tampered / replaced binary** | Same path, different contents after a compromised package or manual copy | `sha256` of the resolved file (pin from a trusted environment with `check -v`) |
| **Version drift** | Image rebuilt with Go 1.27 while the project expects 1.22.x; node 18 vs 22 | `version` constraints (exact, wildcard, ranges, `~`, `^`, `||`) |
| **Host vs sandbox mismatch** | Tests accidentally run on the host instead of the `oss-sandbox` container, using host tools and host credentials | `require_container = true` (or `false` for host-only manifests); detection via `/.dockerenv`, `/run/.containerenv`, `$container`, `/proc/1/cgroup` |
| **Silent misconfiguration** | Typo `sha265 = ...` disables the hash check | Unknown manifest keys are a hard error; invalid constraints, regexes and digests are rejected at load time |
| **Hanging probe** | A tool waits on stdin or the network | Probes run with no stdin and a timeout (`--timeout`, default 10s) |

## Non-goals / limits

- It **executes** each tool with its version arguments. Run it only with manifests you trust,
  and preferably inside the sandbox. A malicious binary can lie about its version; that is
  why `sha256` exists.
- Container detection is heuristic, not a security boundary.
- A hash pins one exact build; it is per-platform and must be updated on upgrade.
- Shared libraries, interpreters' site-packages, and plugins are not verified (future work:
  `ldd`/module lists, SBOM output).
- Prerelease handling is SemVer ordering (`1.3.0-rc1` satisfies `<1.3.0`), not npm's
  "prerelease opt-in" rule.

## Agent protection mode (`toolchain-verify agent`)

AI coding agents (Codex, Claude Code, Cursor, Copilot, Gemini CLI, Windsurf, Cline, ...)
load instruction files and MCP servers from the filesystem and can run commands. The
`agent` subcommand is a **read-only audit** of the local state that those agents trust.
It never executes binaries, never opens credential files and never prints file contents
(only rule names, paths and short pattern labels).

### Threats → rules

| Threat class (documented) | Rules |
|---|---|
| Planted instruction files: an `AGENTS.md` / `CLAUDE.md` / `.cursorrules` / Copilot instructions file dropped into Downloads, Desktop or `/tmp` (including browser-renamed `AGENTS (1).md`) hijacks an agent started there | `instr.untrusted` (fail; content labels such as `pipe-to-shell`, `credential-path`, `exfil-endpoint`, `approval-bypass`, `hidden-unicode`), `cwd.untrusted`, `cwd.ancestor-instructions`, `instr.home` |
| Agent started from an untrusted cwd, or from an unknown checkout carrying its own instruction files | `cwd.untrusted` (`--pre-session` exit 3, `--allow-untrusted-cwd` → warn), `cwd.instructions` (fail with trusted roots, else warn) |
| Planted files remaining on disk after detection | `--quarantine`: move to a quarantine dir as `*.quarantined`, finding → warn (only for `instr.untrusted`, `mcp.untrusted-location`) |
| Prompt injection inside trusted repos (instruction override, hidden Unicode bidi/tag characters, encoded blobs) | `instr.suspicious` (warn) |
| Tampering with instruction or MCP files by other local users or processes | `instr.writable`, `mcp.writable` (world-writable = fail, foreign owner = warn) |
| Prompt injection → RCE in agent stacks (Flowise, Langflow/lfx, PraisonAI, Vibe-Trading, LangAlpha), from the declarative advisory DB | `stack.vulnerable`, `stack.present`, `stack.unknown-version`, `stack.image-unpinned` |
| Agent stacks installed globally or run as services/containers (pip user site, pipx, conda, `npm -g`, snap, systemd units, Docker/Podman images and containers, including `ALLOW_BUILTIN_DEP` in their env) | `stack.*` with host sources, `stack.service`, `inventory.engine-unavailable` (info); `ban_unfixed` turns unfixed advisories into fail |
| Exec-capable stacks running directly on the host | `stack.exec-on-host` (fail when `require_container_for_exec`), `policy.require-container` |
| MCP tool poisoning / rug pull via unpinned `npx`/`uvx`/`pnpm dlx`/`pipx run` packages | `mcp.unpinned` |
| Remote MCP servers over cleartext HTTP, or any remote server | `mcp.remote-cleartext` (fail), `mcp.remote` (info) |
| Approval bypass: MCP `autoApprove`/`alwaysAllow`, Claude `bypassPermissions`, Codex `approval_policy = "never"` + `danger-full-access`, VS Code `chat.tools.autoApprove`, `enableAllProjectMcpServers`, Codex trust for an untrusted dir | `mcp.auto-approve`, `agent.approval-bypass`, `mcp.auto-enable-project`, `agent.trusted-untrusted-dir` |
| Shell bootstrap and container escapes in MCP server commands (`curl … \| sh`, `docker run --privileged`, docker.sock, host root mounts) | `mcp.pipe-to-shell`, `mcp.shell`, `mcp.container-escape` |
| Secrets hard-coded into MCP configs | `mcp.inline-secret` (key names only) |
| MCP configs living in untrusted dirs | `mcp.untrusted-location` |
| Credential theft by an agent or a co-tenant: loose permissions on tokens and keys | `cred.perms`, `cred.owner`, `cred.env` (env var names only) |
| Dependency confusion and MITM in package indexes | `supply.extra-index`, `supply.cleartext-index`, `supply.trusted-host` (pip.conf, uv.toml, `PIP_*`/`UV_*` env) |
| Pickle-based model files from untrusted sources (arbitrary code on load) | `supply.pickle-model` (`.pkl`, `.pickle`, `.pt`, `.pth`-model, `.bin`, `.ckpt`, `.joblib` in untrusted dirs) |
| `.pth` startup hooks executing code at every Python start | `supply.pth-exec` (allowlist for well-known ones) |

### Safety properties of the scanner itself

- **Refuses** to walk or scan credential stores (`~/.ssh`, `~/.gnupg`, `~/.codex`, `~/.claude`,
  `~/.config/gh`, browser profiles, ...) and refuses `/` or `~` as scan targets or trusted
  roots (`ErrRefused`, exit 2). Credential files are only `stat`-ed; `.npmrc`, `auth.json` and
  similar are never opened. A symlink from an instruction file to a credential is flagged, not followed.
- A `toolchain.toml` in an untrusted cwd is **not** auto-loaded (a planted manifest could
  `ignore` everything); `check` likewise refuses it unless `-m` or `--allow-untrusted-cwd`.
- Writes nothing unless `--quarantine` is given. Quarantine only renames regular files or
  symlinks that are still inside an untrusted dir (re-checked at move time) into a dedicated
  dir that may not be `/`, `~`, a credential store, a trusted root or an untrusted dir.
- Container engines are queried with `GET` only (`/images/json`, `/containers/json`,
  `/containers/<id>/json` for stack containers) on a local unix socket; remote `DOCKER_HOST`
  is skipped. From unit and container environments only names listed in `escalate_env` are
  kept; values and other variables are discarded. No binary found by inventory is executed.
- Exit codes: `0` pass, `1` findings failed, `2` usage/policy error or refused target,
  `3` `--pre-session` refused an untrusted cwd. `-q` prints nothing on pass (cron).
- Reads at most 512 KiB per file, bounded depth and entry counts (`scan.truncated`).
- Advisories live in an embedded, strictly validated TOML (`internal/agent/advisories.toml`):
  every entry needs a primary-source reference; conditional or unfixed issues are `warn`
  (e.g. CVE-2026-119978 is escalated to fail only when `ALLOW_BUILTIN_DEP=true` is visible).
  Extra DB files merge via `[agent] advisories` or `--advisories`.

### Limits / deferred

- Does not inspect arbitrary **running processes** (`/proc/*/environ`); containers, systemd
  units and the scanner's env are covered. Versions inside images are taken from the image
  tag only; layers are not unpacked.
- No content-type detection (Magika-style) and no archive unpacking: a malicious
  `AGENTS.md` inside a `.zip` in Downloads is not seen until extracted.
- Pickle detection is by extension in untrusted dirs only; no opcode scanning, no
  safetensors verification, no Hugging Face/plugin signature checks.
- No VS Code / Cursor extension audit, no npm lifecycle-script audit, no project `.npmrc` parsing.
- Docker image tags are compared, not digests; registry provenance is not verified.
- Heuristic content labels have false positives and negatives; they are hints, not a sandbox.
  The real mitigation is running agents and exec-capable tools in a container
  (`require_container = true`).
- The advisory DB is only as fresh as its `updated` date; add local entries for new issues.

## Layout

- `internal/version` — parse/extract versions, compare, constraint grammar.
- `internal/manifest` — strict TOML loading and validation.
- `internal/check` — locate, resolve symlinks, hash, probe, report.
- `internal/agent` — agent-protection audit: policy, instruction files, inventory, advisories, MCP, credentials, supply chain.
- `cmd/toolchain-verify` — CLI (`check`, `agent`/`protect`, `init`, `version`).

## Possible next steps

`pin` subcommand that writes current versions/hashes into the manifest; env-var checks
(`GOFLAGS`, `NODE_OPTIONS`); signed manifests; GitHub Action wrapper; archive (zip) scanning in Downloads; extension audit.
