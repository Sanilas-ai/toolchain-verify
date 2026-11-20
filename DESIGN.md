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
| **Host vs sandbox mismatch** | Tests accidentally run on the host instead of the `oss-sandbox` container, using host tools and host credentials | `require_container = true` (or `false` for host-only manifests); detection via marker files (`/.dockerenv`, `/run/.containerenv`, `/run/systemd/container`), `/proc/1/cgroup`, or overlay on `/` in `/proc/self/mountinfo`. `$container` alone is ignored (trivially spoofable) |
| **Silent misconfiguration** | Typo `sha265 = ...` disables the hash check | Unknown manifest keys are a hard error; invalid constraints, regexes and digests are rejected at load time |
| **Hanging probe** | A tool waits on stdin or the network | Probes run with no stdin and a timeout (`--timeout`, default 10s) |

## Non-goals / limits

- It **executes** each tool with its version arguments. Run it only with manifests you trust,
  and preferably inside the sandbox. A malicious binary can lie about its version; that is
  why `sha256` exists.
- Container detection is heuristic, not a security boundary. Signals used, in order:
  marker files (`/.dockerenv`, `/run/.containerenv`, `/run/systemd/container`), then
  `/proc/1/cgroup` keywords (`docker`, `containerd`, `kubepods`, `libpod`, `lxc`, `podman`),
  then overlay/overlay2 mounted on `/` in `/proc/self/mountinfo`. The `$container`
  environment variable is **not** accepted on its own, so `export container=docker` on
  the host cannot silence `policy.require-container`. A privileged process can still
  plant marker files; treat detection as a convenience check, not isolation.
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
| Agent started from an untrusted cwd, or from an unknown checkout carrying its own instruction files | `cwd.untrusted` (`--pre-session` exit 3, `--allow-untrusted-cwd` → warn), `cwd.instructions` (fail with trusted roots, else warn), `policy.no-trusted-roots` (`--pre-session` with no trusted roots → warn + exit 4 INCOMPLETE; never a silent PASS) |
| Planted files remaining on disk after detection | `--quarantine`: move to a quarantine dir as `*.quarantined`, finding → warn (only for `instr.untrusted`, `mcp.untrusted-location`) |
| Prompt injection inside trusted repos (instruction override, hidden Unicode bidi/tag characters, encoded blobs) | `instr.suspicious` (warn) |
| Tampering with instruction or MCP files by other local users or processes | `instr.writable`, `mcp.writable` (world-writable = fail, foreign owner = warn; editor `settings.json` only when it contains MCP keys) |
| Prompt injection → RCE in agent stacks (Flowise, Langflow/lfx, PraisonAI, Vibe-Trading, LangAlpha), from the declarative advisory DB | `stack.vulnerable`, `stack.present`, `stack.unknown-version`, `stack.image-unpinned` |
| Agent stacks installed globally or run as services/containers (pip user site, pipx, conda, `npm -g`, snap, systemd units, Docker/Podman images and containers, including `ALLOW_BUILTIN_DEP` in their env) | `stack.*` with host sources, `stack.service`, `inventory.engine-unavailable` (info); `ban_unfixed` turns unfixed advisories into fail |
| Exec-capable stacks running directly on the host | `stack.exec-on-host` (fail when `require_container_for_exec`), `policy.require-container` (WARN on host listing each surface; INFO when already in a container), `policy.exec-surface` (INFO per surface: path, kind, why) |
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
  `3` `--pre-session` refused an untrusted cwd, `4` incomplete (`--pre-session` with no
  trusted roots, or a scan coverage gap). `-q` prints nothing on pass (cron).
- Instruction walks under trusted roots default to the current git repository (`--scope=repo`)
  so a wide `--trusted /work` does not scan every sibling checkout; `--scope=trusted-roots`
  restores the full walk.
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
| Provider image template: shared SSH host keys (MITM across all VMs of the image), DSA | `host.ssh-hostkeys-template` (`host vps`) |
| Password / root SSH login left on by cloud-init drop-ins, incl. keyboard-interactive through PAM | `host.sshd-effective` (first value wins across `Include`) |
| Passwordless root via sudo (cloud-init `90-cloud-init-users`) | `host.sudoers-nopasswd` |
| Weak, duplicated or unrestricted root SSH keys | `host.authorized-keys-hygiene` |
| Unexpected listener on a public interface | `host.listeners-policy` (allowlist in the manifest or `--listen-policy`) |
| Vanilla WireGuard classified by DPI | not detected; guidance in [docs/vps-fresh-image-checklist.md](docs/vps-fresh-image-checklist.md) |
| Internet-facing server without firewall, brute-force protection, auto-updates, time sync | `host.firewall-off`, `host.ssh-exposed`, `host.no-bruteforce-protection`, `host.no-auto-updates`, `host.kernel-stale`, `host.ntp-unsynced` |
| git CVE-2026-111760 (code execution on recursive clone) | `host.git-cve-2026-111760` |

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
- `host vps` keeps the same rule: it does not run `sshd -T`, `timedatectl`, `git` or `nft`;
  their outputs are optional inputs (`--sshd-t`, `--timedatectl`, `--git-version`, `--nft`).
  Without them it evaluates `sshd_config` + `Include` drop-ins itself (first value wins,
  `Match` blocks are not applied globally; a `Match` in an included file ends with that file),
  and reads `/run/systemd/timesync/synchronized` and the dpkg git version.

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
On `--hook`, that deny is also a line in the mediator log. `policy check -c`
without `--hook` still prints the shell decision only: it does not ask on
`/dev/tty` and it does not write the log. The hook path is the action pipeline
in the backlog section.

### Limits

- The exec-policy engine sees the command line, not data flow. The post hook
  is what sees the tool result. `bash build.sh`, `python3 x.py`, a Makefile on
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
| Prompt injection in instruction files | `injection.*`: secret-exfil, decode-exec, markdown-exfil, override-action, install-first, config-rewrite, endpoint-redirect, approval-bypass, pipe-to-shell, override, exfil-endpoint. These are correlated signals per paragraph, not single keywords |
| MCP configs: unpinned `npx`/`uvx` runners, typosquats, privileged containers, docker.sock, cleartext remotes | `mcp.*` |
| Agent settings: auto-approve / YOLO, endpoint override, hooks, broad permissions | `agent.*` |
| Editor auto-run (`folderOpen` tasks, disabled workspace trust) | `editor.*` |
| CI: unpinned actions/images, pwn-request, script injection, `write-all` | `gha.*` |
| CI: AI coding agent in the same job as publish secrets or write/OIDC tokens (prompt injection → release backdoor, Depi on Codex, 2026-11-11) | `ci.agent-publish-token` |
| Recursive submodule clones in agent instructions, scripts, workflows (git CVE-2026-111760) | `agent.recursive-clone` |
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
- `agent.tool-update-cooldown` as a check: read agent tool pins (manifest, `package.json`,
  `.tool-versions`, CI `npm i -g …@latest`) and warn when a version is younger than ~48 h
  or unpinned (`@latest`) next to credentials. Needs registry publish times, so it stays
  opt-in/online. Today it is guidance in the README.
- MCP governance gateways, as integration targets and for a detector "MCP without a
  gateway" (agent configs that talk to MCP servers directly instead of through a policy
  proxy). Ideas from Дамагер, links only, nothing cloned or run:
  - [IBM ContextForge](https://github.com/IBM/mcp-context-forge): MCP gateway/registry that
    federates MCP and REST tools behind one endpoint with auth, rate limits and observability.
  - [Lunar MCPX](https://github.com/TheLunarCompany/lunar): MCP aggregator/gateway with
    per-tool access control, audit and traffic policies.
  - [Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit):
    policy enforcement, identity and audit for agent actions and tool calls.
  - [MCP-Defender](https://github.com/MCP-Defender/MCP-Defender): desktop proxy that
    inspects MCP traffic of AI clients and blocks malicious tool calls.
  Detector idea: an `mcp.json` server that is not routed through a configured gateway URL
  (manifest `[agent] mcp_gateway = "..."`) is reported, and `mcp-tools` could pin the
  gateway's `tools/list` instead of each server's.
- Data-driven rule packs (YAML signatures, optional YARA via an external binary in the sandbox).
- Dynamic MCP probe: start a server inside the oss-run sandbox with no network or credentials, call `tools/list` and pipe the result into `mcp-tools`.
- OCR for instruction images, and scanning inside archives (zip/tar, bounded).
- VS Code/Cursor extension (VSIX) audit, browser extension manifests.
- A DLP egress proxy for agents (pipelock-style), possibly shared with browser-control.
- Landlock/seccomp or microVM sandbox profiles (nono, microsandbox, OpenSandbox ideas).
- Signed manifests and IOC DB signatures; registry provenance and container signature checks (golf-style).
- More model formats: ONNX, Keras H5, TF SavedModel lambda layers (modelscan/fickling ideas).
- Import a red-team corpus (agentdojo/spikee/PurpleLlama prompts) as offline regression fixtures for the detectors.
- Done: our own CI actions are pinned to full commit SHAs (with version comments).

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
- `internal/pipeline` — admission, subject, argument filter, return-path hashes, mediator log.
- `internal/trace` — session-journal reader (`trace`, `trace watch`).
- `internal/models` — model artifact scan: format sniffing, pickle opcode walk, safetensors/GGUF checks, Ollama store/API report, external scanners.
- `internal/reposcan` — repository scan (`scan`) and MCP tool-list lint (`mcp-tools`); IOC DB `iocs.toml`.
- `cmd/toolchain-verify` — CLI (`scan`, `mcp-tools`, `mcp-lock`, `check`, `pin`, `agent`/`protect`, `exec-lint`, `docker`, `host`, `policy`, `posture`, `trace`, `toolcall`, `models`, `init`, `version`).

## Possible next steps

Done: `pin` subcommand that writes current versions/hashes (and optionally paths) into the
manifest. Still open for `pin`: pinning `version_regex`/`version_args` for new tools,
`--json` output, and adding tools that are not yet in the manifest.

Next: env-var checks
(`GOFLAGS`, `NODE_OPTIONS`); signed manifests; GitHub Action wrapper; archive (zip) scanning in Downloads; extension audit.

## Accepted direction (2026-11-16)

Ship the verifier fixes below and a session trace. Do **not** put an LLM
supervisor on top of either. The session journal is untrusted input: a poisoned
tool result or instruction that already steered the working agent will ask a
watcher model to ignore the finding. Allow, deny, and stop come from this
process's exit code. A model may only restate a finding the verifier has
already emitted. It does not grant exceptions and it does not decide to kill.

`mcp.toxic-flow` stays a static capability check on a saved `tools/list`. The
concrete source → sink check moves to the trace, where a real session either
did or did not connect the calls.

### Session trace (`toolchain-verify trace`)

Watch an agent that is already running. Tail its session journal and treat
each new tool call as an event (name, class, arguments).

Journals, and only these: Claude Code `~/.claude/projects/**/*.jsonl`, Codex
session files, Cursor agent transcripts. `CredentialDirs` today refuses all of
`~/.claude` and `~/.codex`; the trace is the exception that opens the journal.
`auth.json`, `.credentials.json`, and the other credential files stay unopened.
Evidence is redacted the same way as `scan`. Argument text is not printed.

An action is unauthorized when any of these hold:

- the shell command fails `execpolicy`;
- a path argument hits a credential store or leaves `trusted_roots`;
- a span of an untrusted tool result (page, issue, mail) reappears in an
  outbound or out-of-repo write argument.

`trace watch` follows the live file. Exit `1` on the first such event. The
journal line is usually appended after the tool returns, so the first action
has already run. `trace` on a finished journal is the same rules without the
tail.

`trace` is the client's journal. Its job is to be that journal. It is not the
process the call must pass through, and a missing or rewritten journal is not
a pass. The check that can block a call before it runs is the action pipeline
below, and only when the client invokes the hook.

### Verifier fixes (same decision)

- `injection.pipe-to-shell`: judge the sentence. `never` / `don't` / `не` /
  `никогда` in that sentence, or a match that sits only inside a fenced block,
  is info. Fixtures from `docs/reports/2026-11-mass-scan.md`.
- `execpolicy`: an unexpanded `argv[0]` (`$VAR`, `${VAR}`, including after
  `sudo` / `env`) is deny, same path as an unparsable command.
- `exec-lint`: a `toolchain-verify:sandboxed` marker counts only on the call
  line and only next to a wrapper named in the policy. `shell=True`, `sh -c`,
  and `eval` on that line still fail. A function that contains a sink is a
  dirty name; a call of that name from an LLM file in the same directory is
  `exec.unwrapped`.
- One `findings.Finding`. Extra fields use `omitempty`. `rule`, `severity`,
  `path`, `message` stay. Reports gain `schema_version`.
- `host net` reads the local engine socket with the same GET queries as
  `docker`. A published `HostPort` on `0.0.0.0` or `::` is `net.docker-bypass`
  (fail). A remote `DOCKER_HOST` is not contacted.
- `policy.db-stale` (warn) when `advisories.toml` or `iocs.toml` `updated` is
  older than `agent.db_max_age_days` (default 45). No network. `--strict`
  promotes it to fail.
- Windows journal/repo open uses `FILE_FLAG_OPEN_REPARSE_POINT` and refuses a
  reparse point. If that open is impossible, the verdict is INCOMPLETE, not PASS.
- `agent.hook-binding`: `.claude/settings.json` and `~/.cursor/hooks.json` must
  invoke this binary with `--hook claude` or `--hook cursor`. Otherwise
  `agent.hook-missing` or `agent.hook-substituted` (fail). Secret files are
  not opened.
- `posture`: one command. It runs admission, then `--pre-session`,
  `policy validate`, `mcp-lock --lock`, and the database-age check. The exit
  status is the worst of the five. Admission is the detector added for the
  action pipeline (`admit.container`, `admit.credential`, `admit.guard`,
  `admit.env`, `admit.network`).
- `instr.pin`: SHA-256 of the instruction files the agent will load, in a lock
  beside `mcp.lock.json`. Later runs fail on `instr.drift`.
- `toolcall scrub`: run a tool result through the hidden-Unicode strip and the
  `injection.*` signals before it is returned to a context. Exit `1` when
  override, exfil, or hidden Unicode remains. The model is not executed.
- `policy --follow-script`: for `bash` / `sh` / `python` / `node`, if the
  argument is a file inside the cwd, read it up to the size cap and run
  `SplitShell` once. One file deep. Unreadable means deny.
- `cred.transcript-perms`: stat session directories only. World-readable or a
  foreign owner is fail. Contents stay unopened.
- `scan --files -`: paths on stdin. The scanner still does not invoke git; a
  pre-commit wrapper may pass `git diff --name-only`.

## Backlog: testing and tracking model behavior (2026-11-16)

Three roles. The analyzer and the journal were already shipped. The action
pipeline on `policy --hook` and `posture` is shipped. It runs when the client
invokes the hook. It is not a process the call is forced through.

| Role | Question it answers | Shipped as |
|---|---|---|
| Static analyzer | What do the files allow before a session? | `agent`, `scan`, `exec-lint`, `models`, `host`, `docker`, and `posture` admission |
| Journal | What did the client agree to write down? | `trace` |
| Proxy | May this call leave, and what came back? | `policy check --hook claude\|cursor` before the call, `claude-post` / `cursor-post` on the way back. The client must invoke the hook |

No second model sits on this path. A poisoned tool result that already steered the working agent will ask a watcher model to ignore the finding. Allow, deny, and the record come from this process.

Nothing stands on the path by default. `policy --hook` and `toolcall` run only when a client calls them. An omitted call is not a pass of this check. The check did not run.

### Action pipeline (shipped)

Order, for one call the client submits: admission, then the mediator, then the subject and the exec policy, then the argument filter, then the tool, then the scrub of the result, then the same mediator record. `trace` stays beside the pipe.

Admission is `posture`, before any tool call. `--agent-netns` is `none` or anything else; an empty value is a fail (`admit.network`). With `require_container` set, a process that is not in a container is `admit.container`. `admit.credential` fires when this uid can open `~/.ssh/id_ed25519`, `~/.ssh/id_rsa`, `~/.claude/.credentials.json`, or `~/.codex/auth.json`. `admit.guard` fires when this uid can append `~/.claude/settings.json`, `~/.cursor/hooks.json`, `~/.config/toolchain-verify/exec-policy.toml`, or the file given to `--policy`. `admit.env` fires when a name or a value in the operator-supplied `--agent-env` file matches a token, a key, or a known secret prefix (`AKIA`, `ghp_`, `github_pat_`, `sk-`, `xox`). The finding records the variable name. The value is not printed. `/proc/*/environ` is not read. `posture` then runs the four older checks. The exit status is the worst of admission and those four.

The hook writes `--mediate-log` before it returns allow. The path must sit outside `--repo`. A credential basename is refused. On Unix the append is `O_APPEND` with `O_NOFOLLOW`, mode `0600`. One JSON line holds `rule`, `verdict`, `tool`, and `subject` (`uid`, `container`, `repo`, `session`). `source` is set on the return path to the `tool_use_id`. The line does not hold argument text or a tainted span. A missing policy or an unparsable payload appends a deny and blocks (Claude exit 2, Cursor `{"permission":"deny"}`).

The subject is the process running the hook: uid, whether `check.DetectContainer()` is true, `--repo` (default cwd), and `--session`. A non-empty `--allow-subject` list allows only a matching uid, container flag, and repo. The session is recorded and is not part of the match. An empty list adds no gate. A mismatch is `pipeline.subject`.

Arguments are judged for every class, including a calm tool name. A credential fragment (`/.ssh/`, `/.gnupg/`, `/.aws/`, `auth.json`, `.credentials.json`, `/.config/gh/`, `/.kube/`, `.ssh/id_`) is `pipeline.path`. With a non-empty `--trusted` list, an absolute path outside those roots is the same rule. An empty trusted list skips the outside-root check, so `Read` of `/etc/passwd` with no `--trusted` stays allow. Class `other` is `pipeline.class` and is not an allow. Shell still goes through `execpolicy`. A shell allow also needs `--approve` or a human `yes` on `/dev/tty` (`--tty-file`, default `/dev/tty`). Silence or `no` is `pipeline.tty`. The command is shown on that terminal so the human can answer. It is not copied into the log.

`claude-post` and `cursor-post` run `toolcall.Scrub` on `tool_response`. A failing scrub denies with that rule. A tool classed `untrusted` is remembered as SHA-256 hashes of 1–3 word phrases, 8–200 bytes, at most 64 phrases, under its `tool_use_id`, in `<mediate-log>.state` (mode `0600`, symlink refused, at most 32 results). The text is not stored. Without `--mediate-log` an untrusted result that scrub would allow is `pipeline.flow`. A later call whose arguments repeat a remembered phrase is `pipeline.flow`, and `source` is that id.

Editor writes, `git push`, the clipboard, the browser, and the model-provider request are not on this hook. Admission is what keeps those closed: no secret mounted, network `none`, and the policy and the hook outside the tree the agent writes.

Shipped surface:

- static analysis of the toolchain and of LLM-adjacent code (`check`, `pin`, `exec-lint`);
- Docker host hygiene, host security, model-artifact scan, repository scan;
- MCP tool-list lint and MCP lock;
- `toolcall` parser, schema gate, and scrub;
- `execpolicy`, called by the hook as Claude `PreToolUse` or Cursor `beforeShellExecution`, and by `policy check -c` with no mediator and no tty;
- the action pipeline above (`posture` admission, mediator log, subject, argument filter, post-hook scrub, flow by `tool_use_id`);
- `trace`, a journal written after the fact.

### Recorded hypotheses

Each line was a guess about the empty cell. The status is what the code does now. A line that is still open stays here so a later test can confirm or drop it.

- **Three locks. Shipped on the hook, and the third is partial.** Block before the tool runs: a missing policy, a bad payload, or a deny returns before the client is told to proceed. Filter the arguments and the bytes on the way back: `pipeline.path`, `pipeline.class`, scrub, `pipeline.flow`. The mediator log sits outside the repository, and a rewritten client journal does not change it. The same uid can still kill the hook process or skip the call. Skipping the call does not make this check pass.
- **A subject. Shipped as four fields.** uid, container flag, repository root, and a session id. `--allow-subject` matches the first three. The session is recorded and is not part of the match. An empty allow list adds no gate. This is not a separate credential identity.
- **The data, not the capability. Partial.** The post hook scrubs the result and remembers hashes of an untrusted result under `tool_use_id`. A later call that repeats a phrase is `pipeline.flow`. `mcp.toxic-flow` is still a static check on a saved `tools/list`. Bytes that move through the editor or the model provider are not seen.
- **Secrets unreachable from the start. Partial.** Admission fails when the uid can open a credential, can append the hook or the exec policy, when `--agent-env` contains a secret, when the network is not `none`, or when `require_container` is set and this process is not in a container. The check does not move the process into a container. The container with no secrets and no network remains the barrier.
- **Every exit, not only MCP and shell. Still open.** The hook sees the calls the client submits. An editor write, `git push`, the clipboard, the browser, and the model-provider request that never arrive as a hooked call stay outside it.
- **The tool process's own rights. Still the isolation boundary.** The hook may allow a calm tool name while that server, running as the user, opens `~/.ssh` itself. `pipeline.path` denies a credential path in the arguments. It does not constrain the tool's own code.
- **A person, on a channel the model cannot write. Shipped for a shell allow on the hook.** The hook denies unless `--approve` is set or the human answers `yes` on `/dev/tty`. Silence is `pipeline.tty`. `policy check -c` without `--hook` does not ask. The answer is not written into the mediator log.
- **The running permission set. Still open as a read of another process.** `/proc/*/environ` is not read. The operator passes `--agent-env`. `cred.env` still looks at the scanner's environment.
- **Default allow of the substrate. Still true off the hook.** `policy check -c` follows the exec policy, whose default for an unmatched command can be `host`, with no subject gate and no tty. On the hook, a shell allow still needs the human, a non-empty `--allow-subject` can refuse the uid, and class `other` is deny.
- **The agent is the user. Still open for editor writes.** The hook judges the calls it is given. Harm in ordinary editor actions is not a hooked call.
- **The agent rewrites its own guard. Partial.** `admit.guard` fails when this uid can append the hook file or the exec policy. `instr.pin` / `instr.drift` catches a changed pin on the next audit and does not stop the live write of the rules the next session will load.
- **Egress of bytes, not of actions. Still open.** A secret that has entered the context window leaves on the next request to the model provider. The hook does not see that stream.
- **The provider channel. Still open.** A local hook does not see the request to the model provider. The secret the agent read leaves inside the prompt.
- **The fourth question.** The analyzer answers "what could this agent do here?". The journal answers "what did the client claim happened?". The hook answers "may this call proceed?" for a call the client submits. The cell that stays open is the authority the process already has. Admission reports it. The container is what removes it.

### One hole, named

One hole has two names: **the proxy's own record** and **the process's ambient authority**. Do not split it into two roadmap items. This is the recognition, not a new plan.

`trace` is the client's diary. The hook writes a different file. After an incident, a hook with no log of its own would leave only the client's version of what happened. `--mediate-log` is that record: the process on the path appends allow or deny, and the tests are that a fake allow in the client journal leaves the log unchanged and that deleting the client journal leaves the deny in place. The log has to live in a directory the agent cannot write. The same uid can delete a file it can write.

The other face is the authority the process already has before any call. While the agent runs as the user, it can read the home directory, rewrite the hook, and open the network without asking. A missed call is unnecessary. Admission reports that condition and does not remove it. The analyzer, the journal, and the hook are rails around that fact. The control is a process that does not have the user's ambient authority. The container with no secrets and no network is that boundary.

### Three locks, in this order

These are the tests of one model action. A fixture is one call: tool name, arguments, and optionally the previous untrusted result. The judge is the exit code and the mediator log, never another model.

1. **Block before the action does anything.** The call does not reach the tool until the hook returns allow. No answer, an unreadable policy, or an unparsable command is deny, and the mediator log records that deny. A `trace` line that appears only after the tool has run means the journal saw the call too late. Claude `PreToolUse` exit 2 and Cursor `beforeShellExecution` `deny` are the clients that can hold the call.
2. **Filter the action itself, and the bytes on the way back.** The hook sees the command line, the paths, and the arguments. `Read` of `~/.ssh/id_ed25519` is `pipeline.path` because of the path. Class `other` is `pipeline.class`. On the way back, hidden Unicode, an instruction override, or a secret fragment is deny (`toolcall` scrub), and a later call that repeats a remembered phrase is `pipeline.flow`. Fixtures go both ways: a calm name with a credential path denies, and `Read` of `/etc/passwd` with no `--trusted` allows.
3. **The subject must not be able to switch the observer off.** The mediator log is outside `--repo`, a symlink at that path is refused, and a fake allow in the client journal does not change the log. `admit.guard` fails when this uid can append the hook or the exec policy. The same uid can still kill the hook process or skip the call. An absent client journal is not a pass of `trace`. An omitted hook call is not a pass of the hook. The directory of the log has to be one the agent cannot write; the binary does not create that protection by itself.

### Ambient authority, before any call

This is one face of the hole named above, not a separate project. The forgotten question: in whose name can the process already read the home directory, rewrite the hook, and open the network, without making a call at all? A missed call is unnecessary while the agent runs as the user. `Read` of a key is dangerous because the process is allowed to open the key.

The boundary is the container with no secrets and no network. `posture` runs the tests below and fails even when the journal is empty. Passing them does not put the process in that container.

Tests, with no tool call in the fixture:

- the agent uid can open a credential file;
- the agent uid can write the hook file or the exec policy;
- a credential or a token is in the agent environment;
- the agent network namespace is not `none`.

Each one is a fail even though the journal is empty.

### The record the agent cannot write

This is the other face of the same hole. `trace` is written by the client. The hook writes `--mediate-log`: append-only, outside `--repo`, credential basenames refused, `O_NOFOLLOW` on Unix. The line holds the rule, the verdict, the tool name, and the subject. It does not hold argument text or the tainted span. Tests: the agent appends a fake allow to its own journal and the mediator log is unchanged; the agent deletes its journal and the mediator log still has the deny. The return-path file `<mediate-log>.state` stores hashes only and refuses a symlink.

### Holes that stay on `trace`

`trace` keeps these behaviors. They are what a journal does. The hook answers the same questions with its own rules and does not turn `trace` into a proxy.

- A `tool_result` in the journal is not tied to its `tool_use` by id. The hook keys hashes by `tool_use_id`.
- The `trace` command does not accept trusted roots. The hook does (`--trusted`).
- Journal taint is whitespace-separated tokens of 24–200 bytes, at most 64. The hook counts 1–3 word phrases of 8–200 bytes, at most 64 phrases and 32 results.
- The journal is opened with `os.Open`. Refusal is by basename. The mediator log refuses a symlink at the final path.
- `trace` exit 1 does not signal the agent. This process does not have the agent's pid. The hook's exit code is what the client uses to block the call before it runs.

### Left as research

- TaskTracker-style activation probes on local-model hidden states
  ([microsoft/TaskTracker](https://github.com/microsoft/TaskTracker)). Needs
  llama.cpp activations and a trained probe. Not a watcher, and not on the
  verdict path.
- A written comparison with NeMo Colang
  ([NVIDIA-NeMo/Guardrails](https://github.com/NVIDIA-NeMo/Guardrails)) may
  document which guarantees the deterministic rules already give. Colang does
  not become the allow/deny layer.
