# toolchain-verify

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

```bash
go install github.com/Sanilas-ai/toolchain-verify/cmd/toolchain-verify@latest
# or from a checkout
go build -o bin/toolchain-verify ./cmd/toolchain-verify
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
toolchain-verify agent -m examples/agent-protect.toml --json
toolchain-verify agent --list-advisories       # show the built-in advisory DB
toolchain-verify agent --pre-session           # cheap cwd-only gate before starting an agent
toolchain-verify agent --quarantine            # move planted instruction/MCP files out of Downloads,/tmp
```

Before an agent session, gate the working directory (exit `3` if cwd is Downloads, Desktop,
`/tmp`, ... or contains a planted instruction file there):

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
with `MANIFEST.tsv` holding source path and SHA-256). It is the only write the tool ever makes;
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
[examples/ci/github-actions-ci.yml](examples/ci/github-actions-ci.yml); copy it to
`.github/workflows/ci.yml`.

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

### Manifest

```toml
require_container = true          # optional: true = must run in a container, false = must run on host

[[tool]]
name = "go"                       # unique; also the command unless `command` is set
version = ">=1.22, <2"            # constraint (see below)
version_args = ["version"]        # default ["--version"]
version_regex = 'go(?P<version>\d+\.\d+(\.\d+)?)'   # optional; default: first X.Y[.Z] in output
path = "/opt/go/bin/go"           # optional glob; `*`, `?`, `**`; relative = to manifest dir or --root
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

To pin hashes: run `toolchain-verify check -v` in a trusted environment and copy the printed `sha256` values.

---

## Русский

`toolchain-verify` — CLI для проверки тулчейна по декларативному манифесту
(`toolchain.toml`): находит каждый инструмент в `PATH` (или в `--root`), запускает
`--version`, сверяет версию с ограничением, путь с шаблоном и, если задан, SHA-256
бинарника. Код выхода `0` — всё в порядке, `1` — есть расхождения, `2` — ошибка
манифеста/аргументов. Есть человекочитаемый и JSON-отчёт (`--json`).

### Быстрый старт

```bash
toolchain-verify init          # создать пример toolchain.toml
toolchain-verify check         # проверить текущее окружение
toolchain-verify check -v      # показать реальные пути (после симлинков) и SHA-256
```

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
  (права 0600, `MANIFEST.tsv` с SHA-256). Это единственная запись, которую делает утилита.
- Инвентаризация хоста (отключается `--no-host-inventory`): pip user site, pipx, conda,
  `npm -g`, snap, юниты systemd (`stack.service`), образы и контейнеры Docker/Podman через
  `GET`-запросы к локальному сокету. Из окружения берутся только имена переменных вроде
  `ALLOW_BUILTIN_DEP`. `ban_unfixed = true` — запрет уязвимых версий без исправления.
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

---

License: [Apache-2.0](LICENSE) · Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)
