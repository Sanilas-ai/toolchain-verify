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
| **Tampered / replaced binary** | Same path, different contents after a compromised package or manual copy | `sha256` of the resolved file (record from a trusted environment with `pin`) |
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
| Pickle-based model files from untrusted sources (arbitrary code on load) | `supply.pickle-model` (pickle-capable names in untrusted dirs, confirmed by content sniffing: a `.bin` that is safetensors is not flagged; deep checks live in `toolchain-verify models`) |
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
- `supply.pickle-model` sniffs content but only reports; opcode scanning, safetensors/GGUF
  checks and hashing are in `toolchain-verify models`. No Hugging Face/plugin signature checks.
- No VS Code / Cursor extension audit, no npm lifecycle-script audit, no project `.npmrc` parsing.
- Docker image tags are compared, not digests; registry provenance is not verified.
- Heuristic content labels have false positives and negatives; they are hints, not a sandbox.
  The real mitigation is running agents and exec-capable tools in a container
  (`require_container = true`).
- The advisory DB is only as fresh as its `updated` date; add local entries for new issues.

## Code-exec isolation lint (`toolchain-verify exec-lint`)

Threat: an agent or tool feeds model output (possibly steered by prompt injection from a web page,
issue or file) into `subprocess`, `exec.Command`, `child_process` or `eval`. Without isolation that is
remote code execution with the user's privileges, network and credentials.

Approach: a static, line-oriented scan (no AST, no execution). A file is in **LLM context** when it
imports an LLM/agent SDK, calls a known chat-completions endpoint, contains an
`extra_llm_markers` literal, or uses at least two distinct LLM identifiers (`llm`, `tool_calls`,
`generated_code`, `prompt`, ...). Only exec sinks in such files are reported, which keeps build scripts
and CLIs quiet. A sink is accepted when, within 8 lines before / 15 after, an approved wrapper is named,
when a `docker|podman run` invocation (or `containers.run(...)` from the Docker SDK) has all of
`--network none`, `--read-only`, `--cap-drop ALL` and a non-root `--user` (flags may be built elsewhere
in the same file), or when a `toolchain-verify:sandboxed` comment marks a reviewed call.
`--privileged`, `--pid host`, `--network host` and Docker socket mounts make the sandbox a fail.

Limits: no data-flow analysis (a sink in an LLM file is assumed to receive model output; a sink fed
by model output in another file is missed); annotations and wrapper names are trusted; language
coverage is Go, Python, JS/TS and shell; minified lines over 4 KiB are skipped.

## Docker host hygiene (`toolchain-verify docker`)

Threats: containers reachable from the LAN despite ufw (Docker writes its own iptables rules), container
escapes via `--privileged`, host namespaces, dangerous capabilities or a mounted engine socket, silent
image changes through `:latest`, local privilege escalation through `docker` group membership or an
unauthenticated TCP daemon, and exfiltration from agent stacks that have unrestricted egress.

Safety properties: reads `daemon.json` and `docker.service` units (256 KiB max), stats the socket and
queries the **local** Engine API with GET only; container IDs are validated (`[0-9a-f]{12,64}`) before
being used in a URL; remote `DOCKER_HOST` values are reported, never contacted; environment values of
containers are never requested or printed. Nothing is started, stopped, pulled or changed.

Limits: egress is judged by network attachment (`none`, internal networks), not by firewall rules or
proxies; image tags are not resolved against a registry; Kubernetes, containerd without Docker API and
rootless engines of other users are not inspected.

## Host security mode (`toolchain-verify host`)

Goal: show, without root and without changing the machine, how far a developer host lags
behind security fixes and which listening services the firewall does not account for.

### Threats → rules

| Threat | Rules |
| --- | --- |
| Known-exploited kernel bug still running (e.g. Fragnesia, CVE-2026-46300, CISA KEV) | `kernel.floor` (policy-driven: CVE + minimum package version per series), `kernel.reboot-pending`, `apt.reboot-required` |
| Security fixes published but never installed | `apt.security-pending`, `apt.lists-stale`, `apt.no-security-source`, `apt.unattended`, `apt.dpkg-interrupted`, `apt.esm-available` |
| Root-equivalent local escalation paths | `snap.present` (LXD), `group.lxd` |
| Service bound to 0.0.0.0 that only needs localhost (one firewall change or a Docker port rule away from exposure) | `net.unneeded-bind` |
| Service reachable from anywhere | `net.exposed`, `net.public-listener`, `net.no-firewall`, `net.ufw-inactive`, `net.ufw-default-allow` |
| Stale firewall holes | `net.allow-unused` |

Kernel floors live in the manifest rather than the code: CVE fixes land per series and per
flavour (GA 5.15 vs. HWE 6.8), and new KEV entries appear faster than releases. A floor
whose series does not match the running kernel is reported as info so a missing entry is
visible.

### Safety properties

- Pure file parsing; no `exec` of apt/dpkg/ufw/ss/snap. Reads are size-capped (1 MiB for
  small files; Packages indexes are streamed). `/proc/*/fd` scanning (process names) is
  capped and silently skips other users' processes.
- `--root DIR` reads a copied tree (and is how the tests run with fakes).
- Output never includes file contents beyond package names/versions and socket endpoints.

### Limits

- Pending updates come from the last downloaded indexes: if `apt update` has not run, the
  count is low — that is why list age is checked. `.lz4`/`.xz` Packages indexes are skipped
  (Ubuntu stores plain files by default).
- Pending updates compare against security pockets only; `-updates` is out of scope. ESM
  counts are taken from update-notifier's cached text.
- Reconciliation uses ufw's view only. Docker publishes ports through its own iptables
  chains (before ufw), so a container port can be reachable despite ufw; nftables/iptables
  rules outside ufw are not evaluated.
- `matchingAllow` ignores rule order: a deny rule before an allow is not modelled (reported
  as allowed — the conservative direction). Interface (`on eth0`) and destination limits
  are recorded but not used to narrow a match.
- `/etc/ufw/user.rules` is root-only on Ubuntu; without `--ufw-status` the tool reports
  listeners as "reachability unknown".

## Exec policy (`toolchain-verify policy`)

Goal: an agent pre-exec hook that keeps build/install/test commands for untrusted OSS
code inside the sandbox and blocks a short list of host-changing commands, following the
OSS sandbox rules (nothing installed on the host for OSS work; `go`/`npm`/`cargo`/...
only via `oss-run`; no `--privileged` or `docker.sock` mounts; no `gh auth` changes).

Format: TOML, like the rest of the project (one parser, one validation path, comments for
the reasons). It is a separate `[exec_policy]` section so it can live in its own file
under `~/.config` and not inside a repository an agent can edit.

Decision: the command is split into simple commands (pipelines, lists, subshells,
substitutions, process substitution, heredoc bodies that a shell reads, `echo ... | sh`
literal scripts). Each one is unwrapped through `sudo`/`env`/`nice`/`timeout`/`xargs`/
`flock`/`watch`/`eval`/`sh -c` layers and matched (first matching rule wins) on every
layer; the most restrictive verdict over all commands decides. A recognised sandbox
wrapper (bare name resolved via `PATH`, or exact configured path) turns the remainder into
a sandboxed command where only `everywhere` deny rules apply. A path that is named like a
wrapper but is not the configured one (`./oss-run`) is denied.

Fail-closed: unparsable input, an unknown hook payload or a missing policy blocks.

### Limits

- It sees the command line, not data flow. `bash build.sh`, `python3 x.py`, a Makefile on
  the host or an alias can run anything; list such runners as `sandbox` in the policy if
  they matter. It is a guard rail against mistakes and injected instructions, not a
  security boundary — the container is.
- Variable expansion is not evaluated (`$CMD args`), so `default = "host"` lets it through;
  use `default = "sandbox"` for stricter setups.
- Glob patterns over joined arguments are heuristics (`*--privileged*`).
- Inside the sandbox (`/.dockerenv`) everything but `everywhere` rules is allowed.

## Model artifact scan (`toolchain-verify models`)

A read-only inventory and integrity check of model files on a workstation: what is there
(path, size, SHA-256, format), which files can run code when loaded, and whether the Ollama
store is consistent with its manifests and the running API.

### Threats → rules

| Threat | Rule(s) |
|---|---|
| Pickle payload that runs code on `pickle.load` / `torch.load(weights_only=False)` / `joblib.load` | `models.pickle-dangerous` (fail: imports such as `os.system`, `builtins.eval`/`exec`/`getattr`, `subprocess`, `socket`, `runpy`, `torch.hub`, any dunder) |
| Pickle with classes nobody reviewed | `models.pickle-unknown-import` (`unknown_import`, default warn) |
| Pickle-capable format at all (could be swapped later) | `models.pickle` (`pickle`, default warn; info under `trusted` globs or `allow`) |
| Scanner evasion by truncation / unsupported compression | `models.pickle-incomplete` |
| Header/offset tricks in safetensors and GGUF (parser bugs, OOB reads) | `models.safetensors-malformed`, `models.gguf-malformed`, `models.malformed` |
| GGUF chat-template SSTI (CVE-2024-34359, llama-cpp-python) | `models.gguf-template` (fail on `__class__`/`__globals__`/…, warn on `attr` filters) |
| Keras `Lambda` layers (arbitrary Python on load) | `models.keras-lambda` |
| A reviewed file silently replaced | `models.digest-mismatch` (`allow` with a literal path pins SHA-256; HF cache blobs are checked against their names) |
| Writable model dirs / blob store | `models.writable`, `ollama.writable` |
| Broken or tampered Ollama store | `ollama.blob-missing`, `ollama.blob-size`, `ollama.blob-digest` (`--verify-blobs`), `ollama.manifest-escape`, `ollama.manifest-invalid` |
| Model served by an instance whose store we did not see | `ollama.api-unmatched`, `ollama.store-not-found`, `ollama.api-remote` |
| Provenance hints | `ollama.third-party`, `ollama.variant-not-pulled`, `ollama.orphan-blobs`, `ollama.partial`, `ollama.digest-unverified` |
| Identity key readable by others | `ollama.key-perms` (stat only) |
| Second opinion | `models.scanner` / `models.scanner-error` / `models.scanner-missing` (picklescan, modelscan) |

### Safety properties

- **Never unpickles.** The pickle walker models the VM stack and memo for protocols 0–5 to
  resolve `GLOBAL`/`INST`/`STACK_GLOBAL`/`EXT*` names; it executes nothing, bounds stack,
  memo, string sizes and pickle count, and stops on the first malformed opcode while
  keeping what it found. Legacy torch files (several pickles + raw storage) are handled.
- Read-only: files are opened `O_RDONLY`; nothing is written, moved or downloaded. Scan
  roots of `/` are refused; `.git`, `node_modules`, `.ssh`, `.gnupg` are skipped.
- Ollama: only `GET /api/version` and `GET /api/tags`, no redirects, no proxy, 8 MiB cap,
  credentials in the URL rejected. Only `manifests*/` and `blobs/` are read; the identity
  key next to the store is `stat`-ed, never opened. Weight blobs are parsed (header only)
  but re-hashed only with `--verify-blobs`.
- External scanners run with a minimal environment (`PATH`, `HOME`, `LANG`, `NO_COLOR`), a
  timeout and no stdin; they are never installed by the tool.
- Output contains paths, digests, sizes, import names and finding text — never file contents,
  template bodies or API tokens.

### Limits

- The safe/dangerous import lists are heuristic (cf. picklescan). An "unknown" import is
  not proof of malice and a "safe" one is not proof of safety; data-only verdicts hold for
  the scanned bytes only — pin them with `allow`.
- Joblib inline numpy arrays are skipped by length heuristics; xz/lz4-compressed joblib is
  reported as not parsed. Duplicate JSON keys in safetensors headers are not detected.
- ONNX, HDF5/`.h5`, TFLite, CTranslate2 `.bin` are inventoried and hashed but not parsed.
- GGUF v1 is not structure-checked; unknown ggml types skip the tensor-size check.
- Ollama blobs are trusted by name unless `--verify-blobs` (reads every byte; on HP ~112 GiB).

## Repository scan (`toolchain-verify scan`)

A read-only scan of a checkout (your own repository or a third-party clone) for files that
steer coding agents and tools: instructions, MCP and agent configs, editor tasks, CI
workflows, package hooks and skill scripts. Each file is treated as untrusted data.

### Threats → rules
| Threat | Rules |
|---|---|
| Hidden instructions (tag smuggling, bidi, zero-width, variation selectors) | `unicode.*` (emoji ZWJ and RTL/Indic joiners allowed) |
| Instructions hidden in markup (HTML/markdown comments, hidden styles, `<details>`, LaTeX white/phantom, entity runs) | `hidden.*`, `encoding.html-entities` |
| Prompt injection in instruction files | `instr.*`: secret-exfil, decode-exec, markdown-exfil, override-action, install-first, config-rewrite, endpoint-redirect, approval-bypass, pipe-to-shell, override, exfil-endpoint. These are correlated signals per paragraph, not single keywords |
| MCP configs: unpinned `npx`/`uvx` runners, typosquats, privileged containers, docker.sock, cleartext remotes | `mcp.*` |
| Agent settings: auto-approve / YOLO, endpoint override, hooks, broad permissions | `agent.*` |
| Editor auto-run (`folderOpen` tasks, disabled workspace trust) | `editor.*` |
| CI: unpinned actions/images, pwn-request, script injection, `write-all` | `gha.*` |
| Package lifecycle hooks (npm/gem/setup.py/binding.gyp/.pth) that download, decode, exec or exfiltrate | `pkg.*` |
| Skill scripts | `skill.*` |
| Known campaigns (versioned IOC DB `iocs.toml`, every entry with an https source) | `ioc.*` |
| Secrets in configs | `secret.in-config` (evidence redacted) |
| JSON/YAML duplicate keys (parser differential) | `config.duplicate-key` |
| Silent changes between reviews | `control.new/changed/removed` via `--baseline` |

`toolchain-verify mcp-tools FILE` lints an MCP `tools/list` result:
- tool poisoning
- markdown exfiltration
- cross-tool instructions
- schema poisoning, hidden parameters and schema defaults
- homoglyph or invisible tool names
- shadowing
- toxic flow ("lethal trifecta")
- rug pulls against a `--pin` file

### Safety properties
- The scan never runs git or any repository code. It does not follow symlinks; files are opened with `O_NOFOLLOW|O_NONBLOCK`.
- Reads are bounded: max-file-size, max-files, depth, total bytes and a timeout.
- It refuses `/` and `$HOME` as roots.
- Any skipped or unparsable control file makes the verdict **INCOMPLETE** (exit 4), never PASS.
- Images, archives and binaries are reported as coverage gaps. `--strict-coverage` turns them into INCOMPLETE.
- Evidence is escaped (`\u{XXXX}`) and secrets are redacted.
- Output is text, JSON or SARIF 2.1.0.
- IOC hits are evidence of compromise. The tool never deletes or revokes anything; isolate the machine first (the strutil-core payload has a wiper).

### Ideas taken from the catalog (reimplemented, no code copied)
- golf-scanner: MCP config checks, typosquatting and container pinning.
- MCP-Lattice and mcp-scan: tool poisoning, shadowing, rug pull and toxic flows.
- cisco skill-scanner: skill scripts and markdown exfiltration.
- AI-Infra-Guard and PurpleLlama: ASCII smuggling.
- zizmor-style checks: GitHub Actions rules.
- Socket research: the IOC DB.

### Backlog (P1+)
- Data-driven rule packs (YAML signatures, optional YARA via an external binary in the sandbox).
- Dynamic MCP probe: start a server inside the oss-run sandbox with no network or credentials, call `tools/list` and pipe the result into `mcp-tools`.
- OCR for instruction images, and scanning inside archives (zip/tar, bounded).
- VS Code/Cursor extension (VSIX) audit, browser extension manifests.
- A DLP egress proxy for agents (pipelock-style), possibly shared with browser-control.
- Landlock/seccomp or microVM sandbox profiles (nono, microsandbox, OpenSandbox ideas).
- Signed manifests and IOC DB signatures; registry provenance and container signature checks (golf-style).
- More model formats: ONNX, Keras H5, TF SavedModel lambda layers (modelscan/fickling ideas).
- Import a red-team corpus (agentdojo/spikee/PurpleLlama prompts) as offline regression fixtures for the detectors.
- Pin our own CI actions to full SHAs. Currently `gha.unpinned-action` warns on our own `ci.yml`. A push of workflow changes needs a token with the `workflow` scope, so this is deferred.

## Layout

- `internal/version` — parse/extract versions, compare, constraint grammar.
- `internal/manifest` — strict TOML loading and validation; `EditTools`, a line-level
  editor for `[[tool]]` keys used by `pin` (keeps comments/layout, re-decodes the result and
  refuses any change beyond the requested keys).
- `internal/check` — locate, resolve symlinks, hash, probe, report; `Inspect` returns the
  observed facts without comparing them (used by `pin`).
- `internal/agent` — agent-protection audit: policy, instruction files, inventory, advisories, MCP, credentials, supply chain.
- `internal/execlint` — code-exec isolation lint.
- `internal/dockerhost` — Docker/Podman host hygiene (GET-only Engine API client).
- `internal/findings` — shared finding/collector model for the new audits.
- `sandbox` — public Go helper that builds hardened `docker run` invocations.
- `internal/hostsec` — host audit: dpkg versions, apt lists, unattended-upgrades, kernel floors, snaps, `/proc/net` and `ss` parsing, ufw rules/status, reconciliation.
- `internal/execpolicy` — shell command splitter and host-vs-sandbox policy decisions.
- `internal/models` — model artifact scan: format sniffing, pickle opcode walk, safetensors/GGUF checks, Ollama store/API report, external scanners.
- `internal/reposcan` — repository scan (`scan`) and MCP tool-list lint (`mcp-tools`); IOC DB `iocs.toml`.
- `cmd/toolchain-verify` — CLI (`scan`, `mcp-tools`, `check`, `pin`, `agent`/`protect`, `exec-lint`, `docker`, `host`, `policy`, `models`, `init`, `version`).

## Possible next steps

Done: `pin` subcommand that writes current versions/hashes (and optionally paths) into the
manifest. Still open for `pin`: pinning `version_regex`/`version_args` for new tools,
`--json` output, and adding tools that are not yet in the manifest.

Next: env-var checks
(`GOFLAGS`, `NODE_OPTIONS`); signed manifests; GitHub Action wrapper; archive (zip) scanning in Downloads; extension audit.
