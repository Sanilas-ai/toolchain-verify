# Agent isolation & MCP supply-chain rules

Deterministic checks that an AI coding agent runs with real isolation and
that its MCP servers cannot be swapped out from under it. The rules below
read already-parsed config files; nothing is executed and no credential file
is opened. Inspired by Anthropic's [sandbox-runtime](https://github.com/anthropics/sandbox-runtime)
(dual filesystem+network isolation), the OpenAI [Codex](https://github.com/openai/codex)
sandbox×approval model, [docker/mcp-gateway](https://github.com/docker/mcp-gateway)
(per-server containers), [mozilla-ai/mcpd](https://github.com/mozilla-ai/mcpd)
(a lock file for MCP) and [snyk/agent-scan](https://github.com/snyk/agent-scan)
(tool-poisoning / rug-pull). The action pipeline at the end of this page
is the path a client invokes per call. It appends a mediator log and does
not print argument text or secret values.

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

## Action pipeline

Three roles. The static rules on this page answer what the files allow
before a session. `trace` answers what the client wrote in its journal,
usually after the tool has returned. `policy check --hook` answers whether
this call may proceed, and what came back. The hook runs when the client
calls it. It is not a process the call is forced through. No second model
sits on the verdict.

```text
posture admission
  → policy --hook (mediator, subject, exec policy, arguments, tty)
  → tool
  → claude-post / cursor-post (scrub, remember hashes)
  → mediator line
```

`trace` stays beside that pipe.

| Rule | When it fires |
|------|----------------|
| `admit.container` | `require_container` is set and this process is not in a container |
| `admit.credential` | this uid can open `~/.ssh/id_ed25519`, `~/.ssh/id_rsa`, `~/.claude/.credentials.json`, or `~/.codex/auth.json` |
| `admit.guard` | this uid can append `~/.claude/settings.json`, `~/.cursor/hooks.json`, `~/.config/toolchain-verify/exec-policy.toml`, or `--policy` |
| `admit.env` | `--agent-env` has a secret-like name or value; the finding keeps the name |
| `admit.network` | `--agent-netns` is missing or is not `none` |
| `pipeline.path` | an argument names a credential path, or an absolute path outside `--trusted` |
| `pipeline.class` | the tool class is `other` |
| `pipeline.subject` | `--allow-subject` is set and uid, container, and repo do not match |
| `pipeline.tty` | a shell allow has no `--approve` and no `yes` on `/dev/tty` |
| `pipeline.flow` | a later call repeats a phrase from an untrusted result, or the post hook has no mediator log for that result |
| `pipeline.scrub` / `injection.*` | the tool result fails the scrub |

`posture` runs admission and then pre-session, exec-policy validate,
mcp-lock, and the advisory-database age. The exit status is the worst of
the five. `/proc/*/environ` is not read. The operator passes `--agent-env`.

The mediator line is JSON: `rule`, `verdict`, `tool`, `subject`
(`uid`, `container`, `repo`, `session`). On the return path `source` is
the `tool_use_id`. The file is `--mediate-log`, outside `--repo`,
append-only, mode `0600`, `O_NOFOLLOW` on Unix. A credential basename is
refused. A fake allow in the client journal does not change this file.
The state file next to it stores SHA-256 of short phrases (1–3 words,
8–200 bytes, at most 64 phrases and 32 results) and refuses a symlink.
The phrase text is not stored.

Shell on the hook still uses `execpolicy`. A shell allow also needs the
human. Non-shell tools are judged on their arguments, so `Read` of
`/etc/passwd` with no `--trusted` stays allow and `Read` of
`~/.ssh/id_ed25519` does not. `policy check -c` without `--hook` does not
ask on the terminal and does not write the log.

The hook does not see an editor write, `git push`, the clipboard, the
browser, or the request to the model provider. Those stay closed by the
boundary admission reports: a container, no secret mounted, network
`none`, and the hook and the policy outside the tree the agent writes.
The same uid can still kill the hook process or skip the call. Skipping
the call is not a pass. The tool server's own code can still open a file
the arguments did not name. Isolation remains that control. `agent.hook-binding`
still checks that PreToolUse names this binary with `--hook claude`. Wiring
`claude-post` / `cursor-post` is the operator's hook config.
