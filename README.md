# toolchain-verify

[![CI](https://github.com/Sanilas-ai/toolchain-verify/actions/workflows/ci.yml/badge.svg)](https://github.com/Sanilas-ai/toolchain-verify/actions/workflows/ci.yml) [![Release](https://img.shields.io/github/v/release/Sanilas-ai/toolchain-verify)](https://github.com/Sanilas-ai/toolchain-verify/releases/latest) [![License](https://img.shields.io/github/license/Sanilas-ai/toolchain-verify)](LICENSE)

Verify a development toolchain against a declarative manifest — for reproducible
and safer open-source work (CI, Docker sandboxes, fresh laptops).

`toolchain-verify` reads `toolchain.toml`, finds every tool on `PATH` (or under
`--root`), runs its version probe, checks the version constraint, optional path
pattern and optional SHA-256 of the binary, and exits `0` (all good) or `1`
(something is off), with a human-readable or JSON report.

[English](#english) · [Русский](#русский) · [Design / threat model](DESIGN.md)

---

## English

### Install / build

**Release binaries (recommended):**

```bash
TAG=v0.1.0
VER=${TAG#v}
OS=$(uname -s | tr '[:upper:]' '[:lower:]')   # linux | darwin
ARCH=$(uname -m); case "$ARCH" in x86_64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; esac
BASE=https://github.com/Sanilas-ai/toolchain-verify/releases/download/$TAG
curl -fsSL -O "$BASE/SHA256SUMS"
curl -fsSL -O "$BASE/toolchain-verify_${VER}_${OS}_${ARCH}.tar.gz"
sha256sum -c SHA256SUMS --ignore-missing
tar -xzf toolchain-verify_${VER}_${OS}_${ARCH}.tar.gz
sudo install -m 755 toolchain-verify /usr/local/bin/
toolchain-verify version
```

**GitHub Action (one line in CI):**

```yaml
- uses: Sanilas-ai/toolchain-verify@v0.1.0
  with:
    command: scan
    path: .
    format: sarif
```

Full example: [examples/ci/github-action-scan.yml](examples/ci/github-action-scan.yml).
The action downloads the release binary for the runner OS/arch, verifies `SHA256SUMS`,
runs the command, and can upload SARIF to code scanning (`security-events: write`).

**From source:**

```bash
go install github.com/Sanilas-ai/toolchain-verify/cmd/toolchain-verify@v0.1.0
# or from a checkout
go build -ldflags="-X main.buildVersion=0.1.0" -o bin/toolchain-verify ./cmd/toolchain-verify
```


Inside the Docker OSS sandbox (nothing is installed on the host):

```bash
oss-run -C toolchain-verify go test ./...
oss-run -C toolchain-verify go run ./cmd/toolchain-verify check -m examples/oss-sandbox.toml
```

### Usage

```bash
toolchain-verify init                  # write a sample toolchain.toml
toolchain-verify check                 # verify ./toolchain.toml against PATH
toolchain-verify check -m ci.toml -v   # verbose: resolved paths + SHA-256 digests
toolchain-verify check --root /opt/sdk # search /opt/sdk/bin and /opt/sdk instead of PATH
toolchain-verify check --json          # machine-readable report
toolchain-verify pin                   # record installed versions + SHA-256 into ./toolchain.toml
```

Exit codes: `0` all checks passed · `1` a check failed · `2` usage or manifest error.

```
toolchain-verify: examples/toolchain.toml (running in container)
  OK    go       1.27.3   >=1.22  /opt/go/bin/go
  OK    node     22.23.4  >=20    /opt/node/bin/node
  OK    python3  3.10.12  >=3.10  /usr/bin/python3
  FAIL  git      2.34.1   >=3     /usr/bin/git
                                  - version 2.34.1 does not satisfy ">=3"
FAIL: 3 ok, 1 failed, 0 skipped
```

### Agent protection

`toolchain-verify agent` (alias `protect`) is a read-only audit of what AI coding agents
trust on this machine: planted `AGENTS.md`/`CLAUDE.md`/`.cursorrules`/Copilot instruction
files in Downloads, Desktop and `/tmp`; starting an agent from an untrusted directory;
vulnerable or host-installed Flowise / Langflow / PraisonAI (embedded advisory DB with
GHSA/CVE references); MCP configs (cleartext remotes, auto-approve, unpinned `npx`/`uvx`,
inline secrets, world-writable files); approval bypass in Claude/Codex/VS Code settings;
credential file permissions (stat only, never read); pip/uv index confusion, pickle models
and `.pth` hooks. It executes nothing and never prints file contents.

```bash
toolchain-verify agent                         # defaults (+ [agent] from ./toolchain.toml if cwd is trusted)
toolchain-verify agent --trusted ~/src -v      # trust instruction files only under ~/src
toolchain-verify agent --trusted ~/src --scope=trusted-roots -v  # walk every checkout under ~/src
toolchain-verify agent -m examples/agent-protect.toml --json
toolchain-verify agent --list-advisories       # show the built-in advisory DB
toolchain-verify agent --pre-session --trusted ~/src  # cheap cwd-only gate (needs trusted roots)
toolchain-verify agent --quarantine            # move planted instruction/MCP files out of Downloads,/tmp
```

Before an agent session, gate the working directory (exit `3` if cwd is Downloads, Desktop,
`/tmp`, ...; exit `4` / INCOMPLETE if no trusted roots are configured — that used to
pass silently). Pass `--trusted` (or `agent.trusted_roots`) so the gate is complete.
`--scope=repo` (default) limits instruction walks under a wide `--trusted` root to the
current git repository; `--scope=trusted-roots` walks the whole root:

```bash
# ~/.bashrc
codex()  { toolchain-verify agent --pre-session -q && command codex "$@"; }
claude() { toolchain-verify agent --pre-session -q && command claude "$@"; }
```

`--allow-untrusted-cwd` downgrades only `cwd.untrusted` to a warning; planted instruction
files in that directory still fail. Instruction files found inside a cwd that is neither a
trusted root nor an untrusted dir are reported as `cwd.instructions` (fail when trusted roots
are configured, warn otherwise).

`--quarantine` (off by default; `[agent] quarantine_dir`, `--quarantine-dir`, default
`~/.local/state/toolchain-verify/quarantine`) moves files flagged by `instr.untrusted` and
`mcp.untrusted-location` to `<dir>/<UTC timestamp>/<original path>.quarantined` (mode 0600,
with `MANIFEST.tsv` holding source path and SHA-256). It is the only write `agent` makes;
the quarantine dir must not be `/`, `~`, a credential store, a trusted root or an untrusted dir.
Moved findings become warnings.

Host inventory (default on; `--no-host-inventory` or `host_inventory = false` disables it)
adds, read-only: pip user site / pipx / conda, `npm -g` (`NPM_CONFIG_PREFIX`), pnpm/bun/volta
globals, `/snap/*/current`, systemd units (`ExecStart*`, `WorkingDirectory`, `Environment` names
in `/etc/systemd/system`, `/lib/systemd/system`, `~/.config/systemd/user`, ... → `stack.service`)
and Docker/Podman images and containers via `GET` requests on the local engine socket
(`docker_socket = "off"` disables; remote `DOCKER_HOST` is skipped; unreachable engine →
`inventory.engine-unavailable` info). Only the names of `escalate_env` variables (such as
`ALLOW_BUILTIN_DEP`) are kept from unit/container environments, so a Flowise container started
with `ALLOW_BUILTIN_DEP=true` fails on CVE-2026-119978. `ban_unfixed = true` makes every
advisory without a fixed release fail ("ban until fix").
MCP launch commands (`npx`/`uvx`/`pipx run`/`uv tool run`) are matched against the blocklist
(built-in fake MCP packages such as `karma365-mcp` and `dynamic-mcp`) plus `mcp_denylist`
(`mcp.blocklisted-package`, fail). `mcp_reviewed = ["@scope/pkg@1.2.3", "pkg==1.2.3"]`
reports every other launched spec (`mcp.not-reviewed`, warn).

| Exit | `agent` meaning |
|---|---|
| `0` | pass (warnings allowed unless `strict`) |
| `1` | at least one failing finding |
| `2` | usage error, bad policy/manifest, refused target (`/`, `~`, credential store) |
| `3` | `--pre-session` only: cwd is untrusted — do not start an agent |

Cron / CI (quiet on success, so cron mails only on problems):

```bash
# crontab -e
17 8 * * * toolchain-verify agent -q -m ~/open-source-polygon/toolchain-verify/examples/agent-hp.toml
# CI: fail the job on findings, keep the JSON as an artifact
toolchain-verify agent -m policy.toml --no-host-inventory --json > agent-report.json
```

A ready GitHub Actions workflow (gofmt, vet, build, `test -race`, dry agent run) is in
[examples/ci/github-actions-ci.yml](examples/ci/github-actions-ci.yml) and is installed for
this repo as [.github/workflows/ci.yml](.github/workflows/ci.yml); copy it to the same path in
your own repo (pushing `.github/workflows/*` needs a token with the `workflow` scope).

Configure it with an `[agent]` table (see [examples/agent-protect.toml](examples/agent-protect.toml)
and [examples/agent-hp.toml](examples/agent-hp.toml)). Threat model and limits:
[DESIGN.md](DESIGN.md#agent-protection-mode-toolchain-verify-agent).

### Code-exec isolation lint

`toolchain-verify exec-lint [PATH...]` reads Go, Python, JS/TS and shell sources and reports
process execution (`exec.Command`, `subprocess.*`, `os.system`, `child_process`, `execa`,
`Bun.spawn`, ...) and in-process code evaluation (`eval`, `exec`, `new Function`, `vm.*`) **in files
that handle LLM output** (they import an LLM/agent SDK such as `openai`, `anthropic`, `langchain`,
`ollama`, MCP SDKs, call a chat-completions endpoint, or use several LLM identifiers), unless the call
goes through a hardened container:

```bash
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --user 65534:65534 --ipc none --pids-limit 128 --memory 512m --memory-swap 512m --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m IMAGE@sha256:... CMD
```

| Rule | Meaning |
|---|---|
| `exec.unwrapped` | process/shell execution outside a sandbox (`[shell]` label for `shell=True`, `sh -c`, `exec()`) |
| `exec.dynamic-code` | `eval`/`exec`/`new Function`/`vm.*` on LLM output in-process |
| `exec.weak-sandbox` | `docker`/`podman run` (or the Docker SDK) missing `--network none`, `--read-only`, `--cap-drop ALL` or a non-root `--user`; always **fail** with `--privileged`, host namespaces or the Docker socket |
| `exec.wrapped`, `exec.annotated` (info) | call goes through an approved wrapper / is marked `toolchain-verify:sandboxed` |

Report mode (default) prints warnings and exits 0; `--fail` or `[exec_lint] mode = "fail"` turns
findings into a CI gate (exit 1). Approved wrappers: `run-isolated`, `sandbox.Command`/`sandbox.Args`,
`oss-run`, `oss-shell`, `nsjail`, `bwrap`, `firejail`, `runsc`, plus `--wrapper NAME` /
`[exec_lint] wrappers`. Vendored trees (`node_modules`, `vendor`, `.venv`, `site-packages`, ...) and
test files (unless `--include-tests`) are skipped; `/`, `~` and credential stores are refused (exit 2).

Ship-ready wrappers:

- [examples/sandbox/run-isolated.sh](examples/sandbox/run-isolated.sh): `TV_SANDBOX_IMAGE=python:3.12-slim@sha256:... run-isolated.sh [--mount DIR] [-i] -- python3 -c "$code"` (refuses mounting `/`, `~`, system dirs and sockets; warns on unpinned images).
- Go package [`sandbox`](sandbox/sandbox.go): `cmd, err := sandbox.Command(ctx, sandbox.Config{Image: img, Stdin: true}, "python3", "-")` builds the same invocation (rejects root users, socket and system mounts; host env is not passed).

```bash
toolchain-verify exec-lint ./                       # report mode
toolchain-verify exec-lint --fail --json src/ > exec-lint.json   # CI gate
```

### Docker host hygiene

`toolchain-verify docker` (alias `docker-hygiene`) is a read-only audit of the local engine. It reads
`/etc/docker/daemon.json` and `docker.service` units and queries the local Docker/Podman socket with
**GET requests only** (`/info`, `/networks`, `/containers/json?all=1`, `/containers/<id>/json`); a remote
`DOCKER_HOST` is never contacted.

| Rule | Default severity |
|---|---|
| `docker.public-bind`: port published on `0.0.0.0`/`::` (Docker bypasses ufw) | fail (`allow_public_bind` → info) |
| `docker.privileged`, `docker.host-pid`, `docker.socket-mount`, `docker.cap-add` (ALL/SYS_ADMIN/SYS_MODULE) | fail |
| `docker.host-mount`: `/`, `/etc`, `/var/lib/docker`, ... (fail if rw), credential dirs (fail), whole `~` (warn) | fail/warn |
| `docker.latest-tag`: `:latest` or untagged image without digest | warn (`allow_latest`) |
| `docker.group-member`: current user in the `docker` group (root-equivalent) | warn (`allow_docker_group` → info) |
| `docker.daemon-tcp`: dockerd `-H tcp://` / `hosts` without `--tlsverify` | fail (loopback: warn) |
| `docker.socket-perms`: world-writable engine socket | fail |
| `docker.egress`: container with outbound network | info; warn for agent-stack images (Flowise, Langflow, n8n, Open WebUI, OpenHands, Dify, ...); fail for `egress_deny` globs or label `toolchain-verify.egress=none` |
| `docker.host-network`, `docker.host-ipc`, `docker.unconfined` (seccomp/apparmor off) | warn |
| `docker.root-user`, `docker.engine-unavailable` (fail with `--require-engine`) | info |

Stopped containers are reported one severity lower. Configure with a `[docker]` table; HP example:
[examples/hygiene-hp.toml](examples/hygiene-hp.toml).

```bash
toolchain-verify docker -v
toolchain-verify docker -q -m examples/hygiene-hp.toml   # cron: silent unless something fails
```

Exit codes for `exec-lint` and `docker`: `0` pass · `1` failing findings · `2` usage/manifest error or refused target.

### Host security (`host`)

`toolchain-verify host [apt|net]` is a read-only audit of the machine itself. It parses
files only (dpkg status, apt lists, `apt.conf.d`, systemd timer links, `/proc`,
`/etc/ufw`); it never runs `apt`, `dpkg`, `ufw` or `ss`, never needs root and never
changes anything.

- **apt security lag:** pending updates from the `<codename>-security` pocket (installed
  version vs. the downloaded `Packages` indexes, dpkg version rules), age of the security
  `InRelease` (`Date:`), unattended-upgrades health (package, `APT::Periodic`, security
  origin, `apt-daily-upgrade.timer`, last-run stamp), interrupted dpkg, `reboot-required`
  (+ `.pkgs`), ESM-only fixes from update-notifier.
- **kernel CVE floors:** `[[host.kernel_floor]]` entries (CVE, minimum package version,
  kernel series) compared with the running kernel (`/proc/sys/kernel/osrelease` +
  build number from `/proc/version`); also warns when a newer kernel is installed but not
  booted. No CVE is hard-coded.
- **snaps:** warns when the LXD snap (configurable `warn_snaps`) is present or the user is
  in the `lxd` group.
- **listeners vs. ufw:** sockets from `/proc/net/{tcp,udp}{,6}` (or `--ss FILE` with
  `ss -tulnH` output) reconciled with ufw rules (`/etc/ufw/user*.rules`, or
  `--ufw-status FILE` with `sudo ufw status verbose` output when the rules are root-only).

```bash
toolchain-verify host -m examples/host-hp.toml -v
sudo ufw status verbose > /tmp/ufw.txt         # optional: rules are root-only
toolchain-verify host net -m examples/host-hp.toml --ufw-status /tmp/ufw.txt
toolchain-verify host apt --json --strict
```

| Rule | Severity |
| --- | --- |
| `apt.security-pending` | warn (fail at `security_pending_fail`, default 10) |
| `apt.lists-stale` | warn > `lists_max_age_hours` (48), fail > `lists_fail_age_days` (7) |
| `apt.no-security-source` | fail (none) / warn (wrong release) |
| `apt.unattended` | warn when unhealthy (info with `require_unattended = false`) |
| `apt.reboot-required` | warn, fail after `reboot_max_age_days` (7) |
| `apt.dpkg-interrupted`, `kernel.reboot-pending`, `snap.present`, `group.lxd` | warn |
| `kernel.floor` | fail (or `severity = "warn"`) below `min` |
| `net.public-listener` | wildcard listener and ufw off (fail if sensitive) or rules unknown |
| `net.unneeded-bind` | wildcard listener without a ufw allow: bind to 127.0.0.1 |
| `net.exposed` | wildcard listener allowed from anywhere (fail if sensitive, info if `expected_public`) |
| `net.address-listener` | sensitive port (Docker API, Redis, Ollama, ...) on a LAN address |
| `net.allow-unused` | info: allow rule with nothing listening |
| `net.no-firewall`, `net.ufw-inactive`, `net.ufw-default-allow` | warn |

#### Internet-facing server profile (`host vps` / `--profile vps`)

A fresh VPS from a provider image often ships template host keys, password and root
login enabled by cloud-init, no firewall and no brute-force protection. `host vps` (opt-in;
`host all` = apt + net + vps) audits that. It still executes nothing: pass command outputs
for the parts that need root or a daemon.

```bash
sudo sshd -T > /tmp/sshd-T.txt; timedatectl show > /tmp/tdc.txt; git --version > /tmp/git.txt
sudo ufw status verbose > /tmp/ufw.txt; sudo nft list ruleset > /tmp/nft.txt   # optional
toolchain-verify host vps -v --sshd-t /tmp/sshd-T.txt --timedatectl /tmp/tdc.txt \
  --git-version /tmp/git.txt --ufw-status /tmp/ufw.txt --nft /tmp/nft.txt
toolchain-verify host --profile vps --json          # files only
```

| Rule | CWE | Severity | Checks |
| --- | --- | --- | --- |
| `host.ssh-hostkeys-template` | CWE-1394, CWE-321; CWE-327 | warn (HIGH): key comment names another host (e.g. `root@fi-fi1-srv-kvm-272`), key older than the first boot (cloud-init `instance-id`, else `/var/log/installer`, else `/etc/machine-id`), no ed25519 key; **fail**: DSA key | fix: `rm /etc/ssh/ssh_host_*; ssh-keygen -A` |
| `host.sshd-effective` | CWE-309, CWE-307; CWE-250, CWE-284 | **fail**: effective `PasswordAuthentication yes` (also the OpenSSH default when unset), `PermitRootLogin yes`, or `KbdInteractiveAuthentication yes` (alias `ChallengeResponseAuthentication`; default yes) together with `UsePAM yes`, which is password login through PAM | `--sshd-t` output, else `sshd_config` with `Include` expanded in place, **first value wins**, `Match` blocks skipped; the message names the winning `file:line` and the ignored later values (e.g. `50-cloud-init.conf` beats `sshd_config`) |
| `host.kernel-stale` | CWE-1395 | warn | running kernel older than the newest installed `linux-image-*`, `reboot-required`, a pending linux-image security update (with the apt group) |
| `host.no-auto-updates` | CWE-1395 | warn | `unattended-upgrades` not installed, `20auto-upgrades` missing, `Unattended-Upgrade`/`Update-Package-Lists` not `"1"` |
| `host.firewall-off` | CWE-284, CWE-1327 | **fail** | no default-deny input policy in ufw, nftables (`--nft` or enabled `/etc/nftables.conf`) or `/etc/iptables/rules.v4` |
| `host.ssh-exposed` | CWE-1327 | warn (info when ufw allows sshd only from specific sources) | sshd port (from the effective config) on `0.0.0.0`/`[::]` |
| `host.no-bruteforce-protection` | CWE-307 | warn when sshd is exposed | no fail2ban, sshguard, crowdsec, or `ufw limit` on the ssh port |
| `host.sudoers-nopasswd` | CWE-250, CWE-269 | warn: `NOPASSWD` for `ALL` (also through a `Cmnd_Alias`), e.g. cloud-init's `90-cloud-init-users`; info: `NOPASSWD` limited to a command list | `/etc/sudoers` with `@include`/`@includedir` (names with `.` or `~` skipped, as sudo does) and `/etc/sudoers.d`; unreadable files are listed as info (run as root) |
| `host.authorized-keys-hygiene` | CWE-326, CWE-327, CWE-284, CWE-250 | warn: DSA key, RSA key < 2048 bits, the same key twice or in two accounts, root key without `from=`/`command=`; info: per-file count of user keys without `from=`/`command=` | root and accounts with uid ≥ 1000 and a login shell; `authorized_keys` and `authorized_keys2`. No key material or fingerprint is printed |
| `host.listeners-policy` | CWE-1327, CWE-284 | warn: a non-loopback listener not in the allowlist; info: inventory when no policy is set | allowlist from `--listen-policy FILE` or `[host.listen] allowed = ["22/tcp", "443/udp"]`; sockets from `/proc/net/{tcp,tcp6,udp,udp6}` or `--ss` (`ss -tlnp` output); ephemeral-range UDP skipped |
| `host.ntp-unsynced` | CWE-778 | warn | `timedatectl show` `NTPSynchronized=no`/`NTP=no`, or timesyncd without `/run/systemd/timesync/synchronized`, or no NTP client |
| `host.git-cve-2026-111760` | CWE-197, CWE-59 | warn (HIGH; info when `changelog.Debian.gz` lists the CVE) | git below 2.56.1 / 2.55.1 / 2.54.1 / 2.53.1 / 2.52.1 / 2.51.3 / 2.50.2 ([GHSA-vp2w-7xxj-jvxr](https://github.com/git/git/security/advisories/GHSA-vp2w-7xxj-jvxr): code execution on `clone --recurse-submodules`) |

Findings now carry a `cwe` list in JSON (printed with `-v`). Step-by-step checklist for a
fresh VPS, including a note on vanilla WireGuard behind DPI:
[docs/vps-fresh-image-checklist.md](docs/vps-fresh-image-checklist.md).

**Workstation AI/IDE apps (`host apps`).** VS Code < 1.145.3 (CVE-2026-120779), llama.cpp
`llama-server` < b12340 (`--llama-version`), denylisted IDE extensions (trojanized
`anthropic.claude-code` 2.1.312/2.1.313 and `[host.apps] extension_denylist`), the
`svc-telemetry` IoC key, and with `--authorized-keys-baseline FILE` any authorized key that
is not in the baseline. Also in `host apps`: Chrome/Chromium < 157.0.8103.50
(`host.chrome-cve-2026-125350`, KEV; dpkg/snap or `--chrome-version`), PHP below
8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or EOL (`host.php-cve-2026-109618`; distro backports
listed in `changelog.Debian.gz` are info), a user-writable `$PATH` entry ahead of the system
directories (`host.path-user-writable`, `host.path-shadow`; fail when it shadows `sudo`,
`su`, `ssh` and similar), a tampered pyenv/rbenv/nodenv dispatcher or shim or a re-pointed
Homebrew link (`host.version-manager-tamper`), and IDE extension auto-update left on
(`host.ide-extension-autoupdate`). Details and the wfx-loot runbook:
[docs/threat-intel-2026-11.md](docs/threat-intel-2026-11.md).

**Secrets finder (`host secrets`, on demand, never part of `host all`).** It reads well-known
token locations (`~/.cache/huggingface/token`, `~/.git-credentials`, `.env*` up to two levels
below each home, `~/.config/**` without browser profiles and caches, `[host.secrets]
extra_paths`) and the environment's variable names. It reports `file:line`, the credential
kind (Hugging Face, GitHub, OpenAI, Anthropic, Google AI, xAI, Groq, npm, PyPI, exchange API
key, wallet seed/key, git credential) and a redacted form that keeps only the public prefix
(`hf_…[37 chars]`). Values are never printed. `host.secret-file` warns. On a host marked
sandbox/swarm (`[host.secrets] forbid_exchange_keys = true` or `--sandbox-host`), an exchange
or wallet key fails as `host.exchange-key-forbidden`.

Configure with `[host]`, `[host.apt]`, `[host.net]` and `[[host.kernel_floor]]` (see
[examples/host-hp.toml](examples/host-hp.toml)). Build the binary in the sandbox and run
it on the host: the sandbox cannot see the host's packages, sockets or firewall.

### Host-vs-sandbox exec policy (`policy`)

`toolchain-verify policy check` decides whether a proposed shell command may run on the
host or only through the sandbox wrapper (`oss-run`). It parses the command (quotes,
`&&`/`||`/`;`/pipes, `$(...)`, backticks, `<(...)`, heredocs, `sudo`/`env`/`timeout`/
`xargs`/`nohup`/`bash -c` wrappers, `curl | sh`) and never executes it. Unparsable input is
denied (fail closed). Exit code: 0 allowed, 1 blocked, 2 usage/policy error.

```bash
toolchain-verify policy check -m examples/exec-policy-hp.toml -c 'go test ./...'   # exit 1 + oss-run hint
toolchain-verify policy check -m examples/exec-policy-hp.toml -- git status          # exit 0
toolchain-verify policy validate -m ~/.config/toolchain-verify/exec-policy.toml
```

Verdicts: `host` (allowed), `sandbox` (allowed only via a `sandbox_wrappers` prefix or when
the checker runs inside the sandbox — `/.dockerenv` marker), `deny` (needs a human;
`everywhere = true` also applies inside the sandbox, e.g. `gh auth refresh`). Rules are
evaluated top to bottom, the first match wins; the most restrictive segment decides.

The policy is TOML like the rest of the project (an `[exec_policy]` section; it can live in
its own file). Lookup order: `-m`, `$TOOLCHAIN_VERIFY_POLICY`,
`~/.config/toolchain-verify/exec-policy.toml`, then `./toolchain.toml` (trusted cwd only).

Agent hooks (the command arrives as JSON on stdin):

```jsonc
// Claude Code: .claude/settings.json — exit 2 blocks, stderr goes to the model
{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command",
  "command": "toolchain-verify policy check --hook claude"}]}]}}
// Cursor: ~/.cursor/hooks.json — prints {"permission":"allow|deny",...}
{"version": 1, "hooks": {"beforeShellExecution": [{"command": "toolchain-verify policy check --hook cursor"}]}}
```

A missing policy or a malformed payload blocks. The policy is a guard rail against
mistakes and prompt injection, not a sandbox: see [DESIGN.md](DESIGN.md#exec-policy-toolchain-verify-policy).

The hook is the action pipeline. It runs when the client calls it. `trace` is the
client's journal and stays a journal.

```bash
toolchain-verify posture --agent-netns none --agent-env /run/agent.env --trusted /work/repo
toolchain-verify policy check -m policy.toml --hook claude --on-host \
  --mediate-log /var/log/tv/mediate.jsonl --repo /work/repo --session s1 \
  --trusted /work/repo --allow-subject 'uid=1000,container=true,repo=/work/repo'
toolchain-verify policy check --hook claude-post \
  --mediate-log /var/log/tv/mediate.jsonl --repo /work/repo
```

`--mediate-log` must sit outside `--repo`. Each line is the rule, the verdict, the tool
name, and the subject (uid, container, repo, session). Argument text is not copied.
A shell allow needs `--approve` or `yes` on `/dev/tty` (`--tty-file` in tests). `no`
or silence is `pipeline.tty`. A credential path in the arguments is `pipeline.path`.
An unknown tool class is `pipeline.class`. `Read` of `/etc/passwd` with no `--trusted`
stays allow. A non-empty `--allow-subject` allows only a matching uid, container flag,
and repo. The session is recorded and is not part of the match.

`claude-post` and `cursor-post` scrub the tool result before it re-enters the context.
An untrusted result is stored as hashes under its `tool_use_id` when `--mediate-log`
is set. Without that log the post hook denies it. A later call that repeats a
remembered phrase is `pipeline.flow`.

`posture` runs admission first, then pre-session, policy validate, mcp-lock, and the
advisory-database age check. The exit status is the worst of the five. Admission fails
when `--agent-netns` is not `none`, when `require_container` is set and this process
is not in a container, when this uid can open a credential file or append a hook or
the exec policy, or when `--agent-env` names a secret. Values from that file are not
printed. `/proc/*/environ` is not read.

`policy check -c` without `--hook` is the shell decision only: no terminal question
and no mediator log. Editor writes, `git push`, the clipboard, the browser, and the
request to the model provider are not on this hook. `posture` is what reports that
the process can already open a secret or the network before any call.

```bash
toolchain-verify trace session.jsonl       # finished journal, exit 1 on the first finding
toolchain-verify trace watch session.jsonl # follow the live file; the tool has usually already run
```

### Model artifacts

`toolchain-verify models` is a read-only scan of local model files and the Ollama store. It
finds GGUF, safetensors, `.bin`, `.pt`/`.pth`/`.ckpt`, `.pkl`/`.pickle`/`.joblib`, `.npy`/`.npz`,
Keras, ONNX and PaddlePaddle files under the configured roots, records SHA-256, size and path,
and checks content rather than extensions:

- **pickle-based files** (including torch zip checkpoints, compressed joblib and object `.npy`)
  get a static opcode walk that recovers every imported global *without unpickling*:
  `os.system`, `builtins.eval`, `subprocess.*` and similar fail; unknown classes warn;
  known-safe torch/numpy rebuild helpers are reported under `pickle = "warn"|"fail"|"info"`;
- **safetensors**: header length, dtype × shape vs. byte ranges, overlaps, holes, trailing data;
- **GGUF** (v2/v3): header, metadata and tensor bounds, alignment, and Jinja chat templates
  that reach for Python internals (`__class__`, `__globals__`; CVE-2024-34359);
- Keras v3 `Lambda` layers; Hugging Face cache blobs whose content does not match their name;
- optional `picklescan` / `modelscan` when they are on `PATH` (never installed by this tool;
  a warning says when they are missing and the built-in checks are used alone).

The Ollama report reads `GET /api/version` and `/api/tags` on a loopback URL and the store
layout (`manifests/`, `manifests-v2/`, `blobs/`): missing or wrong-size blobs, manifest symlinks
that escape the store, manifest-list variants not pulled, orphaned and partial blobs,
third-party registries, models served by the API but absent from the scanned store, and
the identity key permissions (stat only). `--verify-blobs` re-hashes every blob.

```bash
toolchain-verify models ~/Downloads/model.ckpt            # one file
toolchain-verify models -m examples/models-hp.toml -v --list
toolchain-verify models --ollama-dir /srv/ollama/models --verify-blobs --json
toolchain-verify models --no-ollama --strict ./checkpoints  # warnings fail too
```

Configure it with a `[models]` table ([examples/models-hp.toml](examples/models-hp.toml)):
roots, trusted globs, an allowlist with SHA-256 pins, and fail vs. warn for pickles.
Details: [DESIGN.md](DESIGN.md#model-artifact-scan-toolchain-verify-models).

### Repository scan (`scan`) and MCP tool lint (`mcp-tools`)

```sh
toolchain-verify scan PATH                 # read-only; exit 0 PASS, 1 FAIL, 4 INCOMPLETE
toolchain-verify scan --json PATH > scan.json
toolchain-verify scan --sarif PATH > scan.sarif
toolchain-verify scan --write-baseline base.json PATH; toolchain-verify scan --baseline base.json PATH
toolchain-verify scan --list-iocs
toolchain-verify mcp-tools tools.json --write-pin pin.json; toolchain-verify mcp-tools tools.json --pin pin.json
```

This finds the following:
- hidden or invisible instructions in AGENTS.md, CLAUDE.md, .cursor/rules, SKILL.md and similar files
- risky MCP and agent configs, editor auto-run tasks and unsafe GitHub workflows
- package install hooks
- known IOCs, such as the strutil-core / pystr-codec campaign
- `agent.recursive-clone` (warn, CWE-829/CWE-59, one finding per file): `git clone --recurse-submodules` / `--recursive`,
  `git submodule update --recursive` or `actions/checkout` `submodules: recursive` in agent
  instructions, rules, scripts, Makefiles and workflows (git CVE-2026-111760; real risk only where git < 2.56.1)
- `ci.agent-publish-token` (fail/warn/info, CWE-269/CWE-522): a workflow job runs an AI coding agent
  (Codex, Claude Code, Cursor agent, aider, OpenHands, Gemini CLI, goose, opencode; an actual
  `uses:`/command invocation, not a name in an image or package) while
  publish secrets (`NPM_TOKEN`, `NODE_AUTH_TOKEN`, PyPI, cargo, …) or `id-token`/`contents`/`packages: write`
  are in reach of the same job ([Depi, Backdooring Codex](https://depi.security/blog/20261111-backdooring-codex/)).
  fail: untrusted trigger (issue_comment, issues, pull_request_target, …) with no author_association
  filter and no built-in write check; warn: gated, or protected only inside the action; info: trusted
  triggers only with just `id-token: write`
- `ci.agent-untrusted-trigger` (info): the agent runs on an untrusted trigger (issue_comment, issues,
  pull_request_target, …) with read-only rights and no publish secrets but without an author_association
  filter; prompt injection can still steer its output/comments and spend the API key
- **Agent write rules**, for agents that call write/mutating tools (send, pay, transfer, delete,
  publish). They are declared in an `agent-capabilities.toml`/`.json` manifest
  ([example](examples/agent-capabilities.toml), [design](docs/design/agent-write-rules.md)).
  A manifest violation **fails**. A best-effort code heuristic (Python/JS/TS/Go files that call
  an LLM client) **warns**:
  - `agent.write-policy-code-derived`: the admission policy for write tools must be built by
    code from the tool schemas (`write_policy.source = "schema"`), never authored by a model
    (CapLite, arXiv 2611.17115);
  - `agent.write-plan-frozen-pre-untrusted`: the write plan is committed before the first
    tool-output / untrusted read and never expanded (`write_plan.frozen_before_untrusted_read = true`);
  - `agent.write-args-from-user`: recipient / content / amount / destination arguments come
    from the user (`source = "user"`) or sit behind `human_confirm = true`.

**Agent tool update cooldown** (`agent.tool-update-cooldown`, guidance): do not auto-update
coding agents (Codex CLI, Claude Code, Cursor agent, MCP servers) the moment a release drops.
Pin the version and move to a new release only after about 48 hours, once the release has
been out long enough for a compromised build to be noticed; never let CI install
`@latest` of an agent next to publish credentials.

The scan never executes anything from the repository. See DESIGN.md.

### Agent isolation & MCP lock (`mcp-lock`)

The `agent` audit also checks that agents run with real isolation:
`agent.sandbox-approval-matrix` (the Codex `sandbox_mode` × `approval_policy`
grid), `agent.no-isolation` (sandbox-runtime `~/.srt-settings.json` settings,
`--dangerously-*` flags, Claude `sandbox:false`), `mcp.no-isolation` (a stdio
MCP server run as a bare host process) and `mcp.secrets-in-env` (a secret on
the command line). See [docs/agent-isolation.md](docs/agent-isolation.md) for
the reference matrix and CWE mapping.

`mcp-lock` is a lock file for MCP servers (mcpd-style): it records each
server's launch package, exact version and an integrity hash, so a version
drift or package substitution is caught before the server runs.

```bash
toolchain-verify mcp-lock --write mcp.lock.json                      # record
toolchain-verify mcp-lock --lock  mcp.lock.json                      # verify (CI gate)
toolchain-verify mcp-lock --write mcp.lock.json --tools tools.json   # also pin tool hashes (rug pull)
```

### Manifest

```toml
require_container = true          # optional: true = must run in a container, false = must run on host

[[tool]]
name = "go"                       # unique; also the command unless `command` is set
version = ">=1.22, <2"            # constraint (see below)
version_args = ["version"]        # default ["--version"]
version_regex = 'go(?P<version>\d+\.\d+(\.\d+)?)'   # optional; default: first X.Y[.Z] in output
path = "/opt/go/bin/go"           # optional glob; `*`, `?`, `**`; relative = to manifest dir or --root
                                      # (mismatch errors restate that and show the resolved pattern)
sha256 = "5f5eb6d0…"              # optional digest of the binary (symlinks resolved)
optional = false                  # true: missing tool is SKIP, not FAIL
```

Unknown keys are an error, so a typo never silently disables a check.

Version constraints: `1.22.3` (exact), `1.22` / `1.22.x` / `1.*` (wildcard),
`=`, `!=`, `>`, `>=`, `<`, `<=`, `~1.2.3` (`>=1.2.3 <1.3.0`),
`^1.2.3` (`>=1.2.3 <2.0.0`; `^0.2.3` → `<0.3.0`), AND with space or comma
(`>=1.20, <1.23`), OR with `||` (`^20 || ^22`).

Examples: [`examples/toolchain.toml`](examples/toolchain.toml) (go, node, python3, git),
[`examples/oss-sandbox.toml`](examples/oss-sandbox.toml) (pinned to the sandbox image paths).

### Pinning (`pin`)

`toolchain-verify pin` probes every `[[tool]]` the same way `check` does and writes what
is installed now back into the manifest, in place: comments, key order and all other
sections are kept; existing keys are replaced, missing ones are added at the end of the
tool's entry. Run it in a trusted environment (e.g. inside the sandbox image you build
with), review the diff, commit.

```bash
toolchain-verify pin                          # version = "1.27.3" + sha256 for every tool
toolchain-verify pin --version caret          # version = "^1.27.3" (also: tilde, min, keep)
toolchain-verify pin --tool go --tool git     # only these tools
toolchain-verify pin --path                   # also pin the found binary path
toolchain-verify pin --no-sha256 --dry-run    # show changes, write nothing
```

- Nothing is written if any required tool is missing or its version cannot be read
  (exit `1`); a missing `optional = true` tool is skipped and left unchanged.
- If the manifest sets `require_container` and pin runs in the other context, it refuses
  (exit `2`) so host hashes never end up in a sandbox manifest (`--ignore-container` overrides).
- Like `check`, an implicit `./toolchain.toml` in Downloads, `/tmp`, ... is refused.
- The edit is verified: the rewritten file is decoded again and must differ from the
  original only in the pinned keys, otherwise nothing is written. A symlinked manifest is
  updated through the link; file permissions are kept.

---


### Tool-call parser (small local models)

`toolchain-verify toolcall` keeps the **first complete valid** tool call from
models that do not stop cleanly (LFM3, MiniCPM5, Hermes, LFM2), validates
arguments against a JSON Schema allowlist, strips/flags hidden Unicode, gates
sensitive classes on `/dev/tty`, and validates Obsessive-style grounded
search answers. Formats and stop sequences are pinned from each model's
published chat template — see [docs/toolcall.md](docs/toolcall.md).

```bash
toolchain-verify toolcall profiles
toolchain-verify toolcall parse --profile minicpm5 --tools tools.json --no-tty generation.txt
toolchain-verify toolcall bench --profile minicpm5 --tools tools.json ./transcripts
toolchain-verify toolcall grounded --source page.txt answer.txt
```


## Русский

`toolchain-verify` — CLI для проверки тулчейна по декларативному манифесту
(`toolchain.toml`): находит каждый инструмент в `PATH` (или в `--root`), запускает
`--version`, сверяет версию с ограничением, путь с шаблоном и, если задан, SHA-256
бинарника. Код выхода `0` — всё в порядке, `1` — есть расхождения, `2` — ошибка
манифеста/аргументов. Есть человекочитаемый и JSON-отчёт (`--json`).

### Быстрый старт

Бинарники: [Releases](https://github.com/Sanilas-ai/toolchain-verify/releases) (проверяйте `SHA256SUMS`).
В CI одной строкой: `uses: Sanilas-ai/toolchain-verify@v0.1.0` (см. [examples/ci/github-action-scan.yml](examples/ci/github-action-scan.yml)).

```bash
toolchain-verify init          # создать пример toolchain.toml
toolchain-verify check         # проверить текущее окружение
toolchain-verify check -v      # показать реальные пути (после симлинков) и SHA-256
toolchain-verify pin           # записать текущие версии и SHA-256 в toolchain.toml
```

`pin` обновляет манифест на месте (комментарии и остальные секции сохраняются):
`--version exact|tilde|caret|min|keep`, `--no-sha256`, `--path`, `--tool NAME`, `--dry-run`.
Если какой-то обязательный инструмент не найден или версия не читается — файл не
меняется (код `1`). Запускайте в доверенном окружении (например, в песочнице).

В Docker-песочнице OSS (на хост ничего не ставится):

```bash
oss-run -C toolchain-verify go test ./...
oss-run -C toolchain-verify go run ./cmd/toolchain-verify check -m examples/oss-sandbox.toml
```

### Что проверяется

- **версия** — ограничения `1.22.3`, `1.22.x`, `>=1.20, <1.23`, `~3.10`, `^20 || ^22`;
- **путь** — glob-шаблон (`/opt/go/bin/go`, `/opt/node/**`), сверяется и с найденным, и с реальным путём;
- **хеш** — SHA-256 бинарника после разрешения симлинков;
- **окружение** — `require_container = true/false` ловит запуск «не там» (хост вместо песочницы);
- относительные и пустые элементы `PATH` игнорируются (защита от подложенного бинарника в текущем каталоге);
- неизвестные ключи манифеста — ошибка (опечатка не отключит проверку молча).

Модель угроз — в [DESIGN.md](DESIGN.md).

### Защита агентов

`toolchain-verify agent` (синоним `protect`) — проверка только на чтение того, чему доверяют
ИИ-агенты: подброшенные `AGENTS.md`/`CLAUDE.md`/`.cursorrules`/инструкции Copilot в
«Загрузках», на рабочем столе и в `/tmp` (включая `AGENTS (1).md`); запуск агента из
недоверенного каталога; уязвимые или установленные прямо на хост Flowise / Langflow /
PraisonAI (встроенная база уязвимостей со ссылками на GHSA/CVE); конфиги MCP (удалённые
серверы по HTTP, auto-approve, `npx`/`uvx` без версии, секреты в конфиге, файлы с правом
записи для всех); обход подтверждений в настройках Claude/Codex/VS Code; права на файлы с
токенами (только `stat`, содержимое не читается); подмена индексов pip/uv, pickle-модели и
`.pth`-хуки. Ничего не запускает и не выводит содержимое файлов.

```bash
toolchain-verify agent --trusted ~/open-source-polygon -v
toolchain-verify agent --list-advisories
toolchain-verify agent --pre-session -q && codex   # не запускать агента из «Загрузок»/tmp (код 3)
toolchain-verify agent --quarantine                # убрать подброшенные AGENTS.md/MCP в карантин
```

- `--pre-session` — быстрая проверка только текущего каталога перед запуском агента; код
  выхода `3`, если каталог недоверенный. `--allow-untrusted-cwd` смягчает только
  `cwd.untrusted`, подброшенные файлы инструкций всё равно дают ошибку.
- `--quarantine` (по умолчанию выключен) переносит файлы `instr.untrusted` и
  `mcp.untrusted-location` в `~/.local/state/toolchain-verify/quarantine/<время UTC>/...quarantined`
  (права 0600, `MANIFEST.tsv` с SHA-256). Это единственная запись, которую делает `agent`.
- Инвентаризация хоста (отключается `--no-host-inventory`): pip user site, pipx, conda,
  `npm -g`, snap, юниты systemd (`stack.service`), образы и контейнеры Docker/Podman через
  `GET`-запросы к локальному сокету. Из окружения берутся только имена переменных вроде
  `ALLOW_BUILTIN_DEP`. `ban_unfixed = true` — запрет уязвимых версий без исправления.
- Команды запуска MCP (`npx`/`uvx`/`pipx run`/`uv tool run`) сверяются с блоклистом
  (встроенные фейковые MCP-пакеты `karma365-mcp`, `dynamic-mcp` и др.) и `mcp_denylist`
  (`mcp.blocklisted-package`, fail); `mcp_reviewed` — список проверенных точных версий,
  всё остальное — `mcp.not-reviewed` (warn).
- Коды выхода: `0` — норма, `1` — есть ошибки, `2` — ошибка использования/политики или
  запрещённая цель, `3` — `--pre-session`: недоверенный каталог. `-q` — без вывода при успехе (для cron).

Настройка — таблица `[agent]` (см. [examples/agent-protect.toml](examples/agent-protect.toml)).
Манифест из недоверенного каталога (например, `~/Downloads`) не подхватывается
автоматически. Модель угроз и ограничения — в [DESIGN.md](DESIGN.md).


### Изоляция исполнения кода и гигиена Docker

- `toolchain-verify exec-lint [ПУТЬ...]` — ищет `subprocess`/`exec.Command`/`child_process`/`eval`
  в файлах, которые работают с выводом LLM (импортируют `openai`, `anthropic`, `langchain`,
  `ollama`, MCP SDK и т. п.), если вызов не идёт через защищённый контейнер
  `docker run --network none --read-only --cap-drop ALL --user nobody ...`. Правила
  `exec.unwrapped`, `exec.dynamic-code`, `exec.weak-sandbox`. По умолчанию — отчёт (код 0),
  `--fail` — ошибка для CI. Готовые обёртки: `examples/sandbox/run-isolated.sh` и Go-пакет `sandbox`.
- `toolchain-verify docker` — проверка Docker-хоста только на чтение (GET-запросы к локальному
  сокету): порты на `0.0.0.0` (Docker обходит ufw), `--privileged`, монтирование сокета и
  системных каталогов, образы `:latest` без digest, пользователь в группе `docker`, dockerd на TCP,
  лишний исходящий трафик у контейнеров. Пример для HP — `examples/hygiene-hp.toml`.

### Безопасность хоста (`host`)

`toolchain-verify host [apt|net]` — проверка самой машины только на чтение: разбираются
файлы (статус dpkg, списки apt, `apt.conf.d`, ссылки таймеров systemd, `/proc`, `/etc/ufw`).
`apt`, `dpkg`, `ufw` и `ss` не запускаются, root не нужен, ничего не меняется.

- **отставание по безопасности apt:** ожидающие обновления из `<codename>-security`,
  возраст `InRelease` для security, исправность unattended-upgrades (пакет,
  `APT::Periodic`, security в Allowed-Origins, `apt-daily-upgrade.timer`, время последнего
  запуска), прерванный dpkg, `reboot-required`, исправления только через ESM;
- **минимальная версия ядра по CVE:** записи `[[host.kernel_floor]]` (CVE, минимальная
  версия пакета, серия ядра) сравниваются с работающим ядром; ни одна CVE не зашита в код;
  отдельно — установлено более новое ядро, но не выполнена перезагрузка;
- **snap:** предупреждение, если установлен snap LXD или пользователь в группе `lxd`;
- **порты и ufw:** слушающие сокеты из `/proc/net` (или `--ss FILE`) сверяются с правилами
  ufw (`/etc/ufw/user*.rules` или вывод `sudo ufw status verbose` через `--ufw-status`, если
  правила доступны только root). Слушает на 0.0.0.0 без разрешающего правила — привязать к
  127.0.0.1; разрешено отовсюду — предупреждение (для чувствительных портов — ошибка);
  правило без слушателя — info.

```bash
toolchain-verify host -m examples/host-hp.toml -v
sudo ufw status verbose > /tmp/ufw.txt
toolchain-verify host net -m examples/host-hp.toml --ufw-status /tmp/ufw.txt
```

**Профиль для сервера в интернете (`host vps` / `--profile vps`).** Свежий VPS из образа
провайдера часто приходит с чужими ключами хоста, входом по паролю и под root (через
cloud-init), без firewall и без защиты от перебора. Проверки: `host.ssh-hostkeys-template`
(комментарий ключа с чужим hostname, ключ старше первой загрузки, нет ed25519 — warn; DSA —
fail; исправление: `rm /etc/ssh/ssh_host_*; ssh-keygen -A`), `host.sshd-effective`
(эффективные `PasswordAuthentication yes` / `PermitRootLogin yes`, а также
`KbdInteractiveAuthentication yes` (или старое `ChallengeResponseAuthentication`) при
`UsePAM yes`, ведь это тот же вход по паролю через PAM — fail; по выводу
`sudo sshd -T` через `--sshd-t` или по `sshd_config` с `Include` и правилом «первое значение
выигрывает», поэтому `50-cloud-init.conf` перекрывает строку в `sshd_config`),
`host.kernel-stale`, `host.no-auto-updates`, `host.firewall-off` (fail), `host.ssh-exposed`,
`host.no-bruteforce-protection`, `host.ntp-unsynced` (`--timedatectl`),
`host.git-cve-2026-111760` (git < 2.56.1 и других исправленных веток; `--git-version`),
`host.sudoers-nopasswd` (`NOPASSWD: ALL`, например `90-cloud-init-users` — warn; список
команд — info), `host.authorized-keys-hygiene` (DSA, RSA < 2048, дубликаты, ключ root без
`from=`/`command=` — warn), `host.listeners-policy` (слушатели вне loopback, которых нет в
`--listen-policy` / `[host.listen]` — warn; без политики — info-инвентарь).
У каждой находки в JSON есть список `cwe`. Пошаговый чеклист для свежего VPS и рекомендация
не полагаться на ванильный WireGuard на пути с DPI:
[docs/vps-fresh-image-checklist.md](docs/vps-fresh-image-checklist.md).

**ИИ- и IDE-софт рабочей станции (`host apps`).** VS Code < 1.145.3 (CVE-2026-120779),
`llama-server` < b12340 (`--llama-version`), расширения из денайлиста (троянские
`anthropic.claude-code` 2.1.312/2.1.313 и `[host.apps] extension_denylist`), IoC-ключ
`svc-telemetry`, а с `--authorized-keys-baseline FILE` любой ключ вне эталона (ключи и
отпечатки не печатаются). Также в `host apps`: Chrome/Chromium < 157.0.8103.50
(`host.chrome-cve-2026-125350`, KEV), PHP ниже 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 или EOL
(`host.php-cve-2026-109618`; бэкпорт из `changelog.Debian.gz` — info), записываемый
пользователем каталог в `$PATH` раньше системных (`host.path-user-writable`,
`host.path-shadow`; fail, если он подменяет `sudo`, `su`, `ssh` и т.п.), подменённый
диспетчер или шим pyenv/rbenv/nodenv или перенаправленная ссылка Homebrew
(`host.version-manager-tamper`), включённое автообновление расширений IDE
(`host.ide-extension-autoupdate`). Подробности и чеклист по wfx-loot:
[docs/threat-intel-2026-11.md](docs/threat-intel-2026-11.md).

**Поиск секретов (`host secrets`, только по запросу, в `host all` не входит).** Читает
типовые места токенов (`~/.cache/huggingface/token`, `~/.git-credentials`, `.env*` до двух
уровней вглубь домашнего каталога, `~/.config/**` без профилей браузеров и кешей,
`[host.secrets] extra_paths`) и имена переменных окружения. Сообщает `файл:строка`, вид
ключа и замаскированную форму с одним публичным префиксом (`hf_…[37 chars]`); значения не
печатаются никогда. `host.secret-file` — warn. На хосте-песочнице или рое
(`[host.secrets] forbid_exchange_keys = true` или `--sandbox-host`) ключ биржи или кошелька —
fail `host.exchange-key-forbidden`.

Бинарник собирается в песочнице, а запускается на хосте: из песочницы не видно пакеты,
сокеты и firewall хоста.

### Политика «хост или песочница» (`policy`)

`toolchain-verify policy check` решает, можно ли выполнить команду на хосте или только через
`oss-run`. Команда разбирается (кавычки, `&&`/`;`/конвейеры, `$(...)`, heredoc, обёртки
`sudo`/`env`/`timeout`/`xargs`/`bash -c`, `curl | sh`), но не выполняется; неразбираемое
запрещается. Код выхода: 0 — можно, 1 — запрещено, 2 — ошибка.

```bash
toolchain-verify policy check -m examples/exec-policy-hp.toml -c 'go test ./...'   # 1 + подсказка oss-run
toolchain-verify policy check --hook claude    # PreToolUse-хук Claude Code (exit 2 блокирует)
toolchain-verify policy check --hook cursor    # beforeShellExecution-хук Cursor
```

Политика — TOML, как и остальной проект (секция `[exec_policy]`, можно отдельным файлом
`~/.config/toolchain-verify/exec-policy.toml`). Пример для HP —
[examples/exec-policy-hp.toml](examples/exec-policy-hp.toml): go/node/npm/pnpm/cargo/pip/
pytest/mvn/gradle — только в песочнице; git, gh и `docker ps/logs/inspect` — на хосте;
`sudo`, установка пакетов на хост, `npm -g`, `gh auth refresh/login`, `docker run
--privileged` и монтирование `docker.sock`, `curl | sh` — запрещены. Это ограждение от
ошибок и prompt injection, а не песочница.

Хук — пайплайн действия. Он работает, когда клиент его вызывает. `trace` остаётся
журналом клиента.

```bash
toolchain-verify posture --agent-netns none --agent-env /run/agent.env --trusted /work/repo
toolchain-verify policy check -m policy.toml --hook claude --on-host \
  --mediate-log /var/log/tv/mediate.jsonl --repo /work/repo --session s1 \
  --trusted /work/repo --allow-subject 'uid=1000,container=true,repo=/work/repo'
toolchain-verify policy check --hook claude-post \
  --mediate-log /var/log/tv/mediate.jsonl --repo /work/repo
toolchain-verify trace watch session.jsonl
```

`--mediate-log` лежит вне `--repo`. В строке правило, вердикт, имя инструмента и
субъект (uid, контейнер, репозиторий, сессия). Текст аргумента туда не пишется.
Разрешение shell требует `--approve` или `yes` на `/dev/tty`. Молчание и `no` —
`pipeline.tty`. Путь к секрету в аргументах — `pipeline.path`. Неизвестный класс
инструмента — `pipeline.class`. Непустой `--allow-subject` пропускает только
совпадение uid, контейнера и корня. Сессия записывается и в сравнение не входит.

`claude-post` и `cursor-post` чистят ответ до возврата в контекст. Недоверенный
результат запоминается хешами по `tool_use_id`, если задан `--mediate-log`. Без
журнала такой ответ запрещён. Повтор фразы в следующем вызове — `pipeline.flow`.

`posture` сначала делает допуск, затем pre-session, проверку политики, mcp-lock и
возраст базы. Код выхода — худший из пяти. Допуск не проходит, если сеть не `none`,
если манифест требует контейнер, а процесс вне его, если uid открывает файл секрета
или дописывает хук либо политику, или если в `--agent-env` есть секрет. Значения из
файла не печатаются. `/proc/*/environ` не читается.

`policy check -c` без `--hook` — только решение по shell: без вопроса на терминале
и без журнала посредника. Запись редактора, `git push`, буфер, браузер и запрос к
провайдеру модели этот хук не проводит. `posture` сообщает, что процесс уже может
открыть секрет или сеть до любого вызова.

### Сканирование репозитория (`scan`)

`toolchain-verify scan ПУТЬ` проверяет репозиторий только на чтение и ничего из него не запускает. Он ищет:
- скрытые инструкции для агентов (невидимый Unicode, комментарии, скрытые стили);
- опасные MCP- и агентские конфиги;
- задачи редактора, которые запускаются автоматически;
- небезопасные GitHub workflows;
- хуки установки пакетов;
- известные IOC;
- `agent.recursive-clone` (warn, одна находка на файл): `git clone --recurse-submodules`/`--recursive` и
  `submodule update --recursive` в инструкциях агентов, скриптах и workflow (реальный риск при git < 2.56.1);
- `ci.agent-publish-token` (fail/warn/info): ИИ-агент действительно запускается (`uses:` или команда,
  а не имя в образе или пакете) в том же job, где доступны секреты публикации или
  `id-token`/`contents: write`. fail — недоверенный триггер без фильтра author_association и без
  встроенной проверки прав; warn — есть фильтр или защита только внутри action; info — только
  доверенные триггеры и лишь `id-token: write`;
- `ci.agent-untrusted-trigger` (info): агент запускается на недоверенном триггере только с правами
  на чтение и без секретов публикации, но без фильтра author_association; промпт-инъекция всё ещё
  влияет на его ответы/комментарии и расход API-ключа.
- **Правила для агентов с изменяющими (write) инструментами** (отправка, оплата, перевод,
  удаление, публикация). Они задаются манифестом `agent-capabilities.toml`/`.json`
  ([пример](examples/agent-capabilities.toml), [дизайн](docs/design/agent-write-rules.md)).
  Нарушение в манифесте даёт **fail**, эвристика по коду (Python/JS/TS/Go с вызовом LLM) — warn:
  - `agent.write-policy-code-derived`: политику допуска write-действий строит код из схем
    инструментов (`write_policy.source = "schema"`), а не модель (CapLite, arXiv 2611.17115);
  - `agent.write-plan-frozen-pre-untrusted`: план write-действий фиксируется до первого
    чтения tool output или недоверенного контента и потом не расширяется
    (`write_plan.frozen_before_untrusted_read = true`);
  - `agent.write-args-from-user`: аргументы «кому / что / сколько / куда» берутся из запроса
    пользователя (`source = "user"`), иначе нужен `human_confirm = true`.

Агентские инструменты (Codex CLI, Claude Code, Cursor agent, MCP-серверы) не стоит обновлять
сразу после релиза: закрепите версию и переходите на новую примерно через 48 часов
(`agent.tool-update-cooldown`, рекомендация).

Если какой-то файл не удалось проверить, вердикт будет INCOMPLETE (код 4), а не PASS. Список инструментов MCP (`tools/list`) проверяется командой `toolchain-verify mcp-tools FILE`: она ищет tool poisoning и rug pull (с `--pin`).

### Файлы моделей

`toolchain-verify models` — проверка только на чтение локальных моделей и хранилища Ollama.
Находит GGUF, safetensors, `.bin`, `.pt`/`.pth`/`.ckpt`, `.pkl`/`.pickle`/`.joblib`, `.npy`/`.npz`,
Keras, ONNX и файлы PaddlePaddle в заданных каталогах, считает SHA-256 и размер и смотрит на
содержимое, а не на расширение:

- **pickle** (включая zip-чекпойнты torch, сжатый joblib и `.npy` с object dtype) — статический
  разбор опкодов **без распаковки**: импорт `os.system`, `builtins.eval`, `subprocess.*` и т.п. —
  ошибка; неизвестные классы — предупреждение; безопасные хелперы torch/numpy — по политике
  `pickle = "warn"|"fail"|"info"`;
- **safetensors** — длина заголовка, dtype × shape против диапазонов байтов, пересечения, дыры;
- **GGUF** (v2/v3) — заголовок, метаданные, границы тензоров, выравнивание и Jinja-шаблоны чата,
  обращающиеся к внутренностям Python (CVE-2024-34359);
- слои `Lambda` в Keras v3; блобы кэша Hugging Face, чьё содержимое не совпадает с именем;
- `picklescan` / `modelscan`, если они есть в `PATH` (сам инструмент их не ставит; если их нет —
  предупреждение и только встроенные проверки).

Отчёт по Ollama: только `GET /api/version` и `/api/tags` на loopback и разбор `manifests/`,
`manifests-v2/`, `blobs/` — отсутствующие блобы и неверные размеры, симлинки за пределы
хранилища, не скачанные варианты, «осиротевшие» и недокачанные блобы, сторонние реестры,
модели из API, которых нет в хранилище, права на ключ (только `stat`). `--verify-blobs`
пересчитывает хеши всех блобов.

```bash
toolchain-verify models ~/Downloads/model.ckpt
toolchain-verify models -m examples/models-hp.toml -v --list
```

Настройка — таблица `[models]` ([examples/models-hp.toml](examples/models-hp.toml)): каталоги,
доверенные пути, allowlist с закреплёнными SHA-256, `fail` или `warn` для pickle.

---

License: [Apache-2.0](LICENSE) · [NOTICE](NOTICE) · Contributing: [CONTRIBUTING.md](CONTRIBUTING.md) · Changelog: [CHANGELOG.md](CHANGELOG.md)
