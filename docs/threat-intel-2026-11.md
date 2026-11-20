# Threat-intel rules, November 2026

Rules added from the 2T digests of 2026-11-13 and 2026-11-15. Each rule cites a public
primary source. Fixtures are synthetic: no real stealer code, keys or tokens.

| Threat | Rule | Command | Severity |
| --- | --- | --- | --- |
| GPUStack loopback auth bypass, CVE-2026-102895 (in CISA KEV since 2026-11-09), plus the SAML callback bypass CVE-2026-102894 | built-in advisories `GHSA-gj9m-f8ph-pmhr`, `GHSA-62m9-f875-rqw6` (stack `gpustack`: PyPI `gpustack`, image `gpustack/gpustack`) | `agent` | **fail** (critical) for every version below **2.2.2** |
| VS Code ≤ 1.145.2: a malicious MCP server turns an elicitation notification into a one-click command link (CVE-2026-120779, CVSS 9.6) | `host.vscode-cve-2026-120779` | `host apps` | **fail** below 1.145.3 |
| llama.cpp `llama-server` SSRF through the CORS proxy and media URLs, weak `--cors-origins`, DNS rebinding; MCP tool calls not cancelled on disconnect/timeout | `host.llama-server-stale` | `host apps --llama-version FILE` | **fail** below build b12340; info on b12340+ that v1.0.0 also carries the MCP cancellation and Host check (v1.0.0 removes the deprecated C API) |
| Trojanized `anthropic.claude-code` 2.1.312 / 2.1.313 served by the Cursor marketplace on 2026-10-29 (persistent SSH backdoor) | `host.ide-extension-denylist` (built-in list + `[host.apps] extension_denylist`) | `host apps` | **fail** |
| The same campaign's planted key (comment `svc-telemetry`) | `host.ssh-ioc-key` | `host apps` | **fail** |
| Any SSH backdoor: an authorized key nobody expected | `host.authorized-keys-baseline` | `host --authorized-keys-baseline FILE` (any group) | **fail** per unexpected key; only `file:line` is printed, never the key or its fingerprint |
| wfx-loot (from 2026-11-10): stolen GitHub tokens push a CI secret stealer that reads `toJSON(secrets)`, dumps the environment and deletes its own run and logs | `gha.secrets-dump` (fail), `gha.log-tamper` (fail), `gha.secret-echo` (warn), plus the existing `gha.pwn-request`, `gha.unpinned-action` | `scan` | see rule |
| AI coding agents in GitHub Actions fed untrusted issue/PR/comment text (Codex Action class) | `ci.agent-untrusted-prompt`: **fail** when an attacker-controlled expression reaches the agent's inputs, warn when the job has no author/actor gate | `scan` | see rule |
| npm account hijack: `npx pkg` / `npm i -g pkg` without a version in CI | `gha.unpinned-npx` | `scan` | warn |
| Poisoned post-training weights (about 1% poisoned data is enough for a backdoor that format checks cannot see) | `models.not-allowlisted` with `[models] require_allow = true`: a reviewed SHA-256 manifest (`[[models.allow]]`) is required before a model is run | `models` | **fail** |
| BluePhishing: agents trusted by name only | `mcp.remote-no-auth`: remote MCP server with no Authorization/API-key header and no OAuth config | `agent` | warn |

## Usage

```bash
code --version > /tmp/code.txt; llama-server --version > /tmp/llama.txt 2>&1
toolchain-verify host apps -v --vscode-version /tmp/code.txt --llama-version /tmp/llama.txt \
  --authorized-keys-baseline ~/keys-baseline.pub
```

The baseline is an `authorized_keys`-format file with the keys that are supposed to be
there (keep it off the audited host, e.g. in your password manager). Without
`--vscode-version` the VS Code `package.json` files (deb/rpm, `/opt`, snap,
`~/.vscode-server/bin/*`) are read. Extension directories are read for root and every
account under `/home`: `.vscode`, `.vscode-server`, `.vscode-insiders`, `.vscode-oss`,
`.cursor`, `.cursor-server`, `.windsurf`, `.windsurf-server`.

## wfx-loot: audit runbook (read-only)

The static rules catch the payload when it is still in a workflow file. The campaign
reverted its commits within a minute and deleted the run, so also look at history:

1. Workflow and hook changes since the campaign started, by author:
   `git log --since=2026-11-10 --format='%h %an <%ae> %s' -- .github/workflows package.json '.ci-*.sh'`.
   Anything not by you or a known collaborator needs a look. Typical titles are
   `ci: refresh build cache`, `chore: add ci helper` and `chore: add dependency audit workflow`.
2. Probe PRs: `gh pr list --state all --search "dependency audit notes in:title" --json number,author,headRefName`
   (branch `wfx-docs`).
3. Gaps in run numbers: `gh run list --limit 200 --json number,createdAt`. A missing number
   after 2026-11-10 means a run was deleted.
4. If a payload ran, treat every secret reachable from that job as leaked, including
   ones the workflow never named, and rotate from a trusted machine.

Refs: [GitGuardian](https://blog.gitguardian.com/wfx-loot-a-ci-secret-stealer-pushed-with-stolen-github-credentials/),
[Aikido](https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories).

## Design notes from Дамагер's defensive review (ideas only, no code taken)

- MCP scanners that start stdio servers to list tools should ask first, and their own
  fetches should refuse link-local and metadata addresses and not follow redirects. Our
  `mcp-tools` reads tool lists from files and never starts a server.
- Egress for sandboxed agents should be a fail-closed proxy with an allowlist: if the
  proxy is down, nothing goes out.
- Tool runtimes should be deny-by-default, with each capability (file, network, env)
  granted per tool.
- Backlog: a static agent↔tool graph report (which agent can reach which tool, file and
  secret), and a YARA-like prompt-signature format for injection rules.

## Refs

- GPUStack: [GHSA-gj9m-f8ph-pmhr](https://github.com/advisories/GHSA-gj9m-f8ph-pmhr), [GHSA-62m9-f875-rqw6](https://github.com/advisories/GHSA-62m9-f875-rqw6)
- VS Code: [GHSA-66hq-jw93-462h](https://github.com/microsoft/vscode/security/advisories/GHSA-66hq-jw93-462h), [NVD](https://nvd.nist.gov/vuln/detail/cve-2026-120779)
- llama.cpp: [b12340](https://github.com/ggml-org/llama.cpp/releases/tag/b12340), [v1.0.0](https://github.com/ggml-org/llama.cpp/releases/tag/v1.0.0)
- Claude Code extension: [Cursor notice](https://cursor.com/blog/claude-code-extension-security-notice), [Microsoft analysis](https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/)
- Agents in CI: [depi.security](https://depi.security/blog/20261111-backdooring-codex/)
