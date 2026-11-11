# Agent isolation & MCP supply-chain rules

Deterministic, read-only checks that an AI coding agent runs with real
isolation and that its MCP servers cannot be swapped out from under it. They
read already-parsed config files; nothing is executed and no credential file
is opened. Inspired by Anthropic's [sandbox-runtime](https://github.com/anthropics/sandbox-runtime)
(dual filesystem+network isolation), the OpenAI [Codex](https://github.com/openai/codex)
sandbox×approval model, [docker/mcp-gateway](https://github.com/docker/mcp-gateway)
(per-server containers), [mozilla-ai/mcpd](https://github.com/mozilla-ai/mcpd)
(a lock file for MCP) and [snyk/agent-scan](https://github.com/snyk/agent-scan)
(tool-poisoning / rug-pull).

## Rules

| Rule | Severity | What it catches | CWE |
|------|----------|-----------------|-----|
| `agent.sandbox-approval-matrix` | fail/warn | Codex `sandbox_mode` × `approval_policy` cell is unsafe | CWE-862 |
| `agent.no-isolation` | fail/warn | sandbox-runtime (srt) settings weaken FS/network isolation; `--dangerously-*` bypass flags; Claude `sandbox:false` | CWE-250, CWE-693 |
| `mcp.no-isolation` | warn | stdio MCP server launched as a bare host process (no container / srt) | CWE-250 |
| `mcp.secrets-in-env` | fail | a literal secret passed on the server command line (visible via `ps`) | CWE-214, CWE-312 |
| `mcp.lock` | fail | MCP server version drift / package substitution vs the lock | CWE-829, CWE-1357 |
| `mcp.lock-unpinned` | warn | server launches `pkg@latest` / no version | CWE-494 |
| `mcp.lock-new` / `mcp.lock-removed` | warn / info | server not in / no longer in the lock | CWE-829 |
| `mcp.tool-poisoning`, `mcp.tool-shadowing`, `mcp.rug-pull`, … | fail/warn | hidden `<IMPORTANT>` instructions, "ignore previous", `~/.ssh` read + exfil, shadowing, rug-pull (see `mcp-tools`) | CWE-77, CWE-1427 |

## Codex sandbox × approval reference matrix

`approval_policy` runs across, `sandbox_mode` down. A cell is the effective
containment of a hijacked tool call.

| sandbox_mode ↓ \ approval → | `untrusted` / `on-request` / `on-failure` | `never` |
|---|---|---|
| `read-only` | ok | **warn** — no human gate, but reads only |
| `workspace-write` | ok (recommended) | **warn** — writes run unattended |
| `danger-full-access` | **fail** — no FS/network isolation | **FAIL (critical)** — no sandbox *and* no approvals |

`--dangerously-bypass-approvals-and-sandbox` (Codex) and
`--dangerously-skip-permissions` / `bypassPermissions` (Claude Code) are the
CLI/settings equivalent of the bottom-right cell and always fail.

**Recommended default:** `sandbox_mode = "workspace-write"` with
`approval_policy = "on-request"`; reserve `danger-full-access` for a
disposable container with an egress allow-list.

## sandbox-runtime (srt) settings

`~/.srt-settings.json` uses an allow-only network list and an allow-only
write list, so an empty `network.allowedDomains` denies all network and an
empty `filesystem.allowWrite` denies all writes. The audit flags the
documented isolation-weakening switches (`allowAppleEvents`,
`enableWeakerNetworkIsolation`, `allowNestedUserNamespaces`,
`allowAllUnixSockets`+`enableWeakerNestedSandbox`), a wildcard-all network
entry (no effective allow-list), and an over-broad `allowWrite` root (`/`,
`~`, the home directory, `**`).

## MCP lock (`mcp-lock`)

```bash
toolchain-verify mcp-lock --write mcp.lock.json         # record current servers
toolchain-verify mcp-lock --lock  mcp.lock.json         # verify before starting agents
toolchain-verify mcp-lock --write mcp.lock.json --tools tools.json   # also pin tool-definition hashes
```

Each server is recorded with its launch package, exact version and a sha256
integrity hash of the whole launch spec (command + args + url). A later
verify fails on drift or package substitution and warns on an unpinned
`pkg@latest`. With `--tools` the lock also carries tool-definition hashes so
a changed description (rug pull) fails the verify.
