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
```

Configure it with an `[agent]` table (see [examples/agent-protect.toml](examples/agent-protect.toml)
and [examples/agent-hp.toml](examples/agent-hp.toml)). Threat model and limits:
[DESIGN.md](DESIGN.md#agent-protection-mode-toolchain-verify-agent).

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
```

Настройка — таблица `[agent]` (см. [examples/agent-protect.toml](examples/agent-protect.toml)).
Манифест из недоверенного каталога (например, `~/Downloads`) не подхватывается
автоматически. Модель угроз и ограничения — в [DESIGN.md](DESIGN.md).


---

License: [Apache-2.0](LICENSE) · Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)
