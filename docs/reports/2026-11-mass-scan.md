# Mass scan report — toolchain-verify — November 2026

First public corpus run of `toolchain-verify scan` against **220** popular
open-source repositories (AI agents, MCP servers, LLM tooling, coding agents,
and widely used developer libraries).

Goal: measure how the scanner behaves on real trees, cut false positives, and
publish **aggregate** results. We do **not** name a repository together with a
live exploitable finding (leaked secret, weaponized injection, or a workflow
we have not framed as a known hygiene class). Benign and fixed cases may be
named.

## Methodology

| Item | Detail |
| --- | --- |
| Scanner | `toolchain-verify scan --json` (read-only; never runs repo scripts, hooks, or installs) |
| Versions | Corpus cloned under v0.1.1–v0.1.3 mid-run; every initial **FAIL** was **re-scanned** with **v0.1.3** |
| Selection | 220 repos: curated high-star AI/MCP/devtools set + GitHub code search hits for `AGENTS.md` / `CLAUDE.md` / `.cursor/rules` / MCP configs |
| Clone policy | `git -c core.hooksPath=/dev/null clone --depth 1 --no-recurse-submodules --filter=blob:none`; clone deleted after each scan |
| Host | Isolated Docker OSS sandbox on a dedicated machine; third-party trees treated as hostile data |
| Commit pins | Each result records the shallow HEAD SHA (see private corpus index on the operator host) |

Selection mix (primary reason): curated-must 95 · AGENTS.md 31 · mcpServers 27 ·
cursor-rules 26 · CLAUDE.md 22 · mcp.json 19.

## Headline results (after v0.1.3 FAIL re-scan)

| Verdict | Count | Share |
| --- | --- | --- |
| PASS | 49 | 22.3% |
| WARN | 108 | 49.1% |
| FAIL | 54 | 24.5% |
| INCOMPLETE | 6 | 2.7% |
| TIMEOUT | 3 | 1.4% |
| **Total** | **220** | 100% |

`WARN` is dominated by unpinned GitHub Actions (`gha.unpinned-action`) and
similar hygiene signals — useful, but not “you are owned”.

`FAIL` mixes true risk surfaces (agent hooks that auto-run, approval bypass in
checked-in agent settings, `pull_request_target` / `issue_comment` pwn-request
shapes, skills that tell the agent to `curl | sh`) with remaining false
positives (security docs that *quote* attack phrases, broad instruction
heuristics). See below.

`INCOMPLETE` means the scanner hit a coverage/size limit and refused to call
the tree clean (exit 4) — preferred over a false PASS.

## False-positive reduction (this release train)

We tracked finding-level FAIL counts on the **57 repos that were FAIL in the
first pass**, then re-scanned them with v0.1.3:

| Rule | Before | After v0.1.3 | Δ |
| --- | ---: | ---: | ---: |
| `unicode.tag-smuggling` | 13 | **0** | −100% |
| `skill.secret-exfil` | 9 | **3** | −67% |

Shipped fixes:

- **v0.1.2** — `skill.secret-exfil` requires a *strong* credential path or named
  token. Bare `process.env` / `os.environ` plus HTTP is normal for skill tools
  and no longer fails.
- **v0.1.3** — `unicode.tag-smuggling` FAILs only in agent-control files or when
  decoded Tags carry instruction signals. Test/WPT/fixture paths without
  signals are demoted (Deno WPT hostname fixtures were a clean FP).

Repo-level flips on that FAIL set after v0.1.3: **1 → PASS** (`openai/codex`),
**1 → WARN**, **1 → INCOMPLETE**, **54 remain FAIL** (other rules still fire).

### Named benign / fixed examples (OK to discuss)

- **Deno WPT URL expectations** — Unicode Tag code points in hostname strings
  under `tests/wpt/...` (fixed classification in v0.1.3).
- **Skill scripts that only read env + call HTTP** — treated as FP for
  `skill.secret-exfil` (fixed in v0.1.2).
- **Security advice that quotes `curl \| bash`** — still over-fires
  `injection.pipe-to-shell` on some `AGENTS.md` files that say *never* do that;
  tracked as a follow-up (negation-aware pipe-to-shell).

## What FAIL usually means (classes, not a hall of shame)

Without tying a novel exploit to a named repo:

1. **Agent control plane** — checked-in `.claude/settings.json` hooks,
   `approval` / `bypassPermissions` style knobs, SessionStart/PostToolUse
   scripts under the repo.
2. **Skills as code** — `SKILL.md` + `scripts/` that download-and-run or
   decode-and-exec (Cisco skill-scanner threat model).
3. **GitHub Actions hygiene** — classic `pull_request_target` /
   `issue_comment` checkout of untrusted PR code (`gha.pwn-request`), and
   untrusted `${{ github.event.*.body }}` expansions (`gha.script-injection`).
4. **Instruction heuristics** — override / secret-read / network /
   config-rewrite combinations in agent markdown. High signal when the text
   *directs* the agent; noisy when docs *describe* attacks.

Intentional **fixtures** (doctor samples, risk corpora, attack unit tests)
also FAIL by design — that is success for a scanner, not a vendor emergency.

## Limits

- Rule- and inventory-based: no LLM judge, no live MCP `tools/list` against
  remote servers in this corpus (use `mcp-tools` offline on a saved dump).
- Shallow clones; no full history.
- Large monorepos may hit `INCOMPLETE` or `TIMEOUT`.
- A FAIL is a review queue, not an automatic CVE.

## Reproducing

```bash
# verify release binary
curl -fsSL -O https://github.com/Sanilas-ai/toolchain-verify/releases/download/v0.1.3/SHA256SUMS
curl -fsSL -O https://github.com/Sanilas-ai/toolchain-verify/releases/download/v0.1.3/toolchain-verify_0.1.3_linux_amd64.tar.gz
sha256sum -c SHA256SUMS --ignore-missing
tar -xzf toolchain-verify_0.1.3_linux_amd64.tar.gz

# scan one tree (read-only)
./toolchain-verify scan --json /path/to/checkout > scan.json

# or in CI
- uses: Sanilas-ai/toolchain-verify@v0.1.3
  with:
    command: scan
    path: .
    format: sarif
```

## Follow-ups

- Negation-aware `injection.pipe-to-shell` / approval phrases in control docs.
- Optional baseline mode tuned for “popular monorepo WARN noise”.
- Publish a pinned public corpus list (owner/name@sha) without FAIL detail.
- Broader multi-hundred run after the negation fix.

---

*Operator: Sanilas-ai · Tool: toolchain-verify · Report date: 2026-11-09 (Europe/Moscow).*
