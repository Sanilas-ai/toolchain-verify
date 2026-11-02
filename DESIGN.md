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

## Layout

- `internal/version` — parse/extract versions, compare, constraint grammar.
- `internal/manifest` — strict TOML loading and validation.
- `internal/check` — locate, resolve symlinks, hash, probe, report.
- `cmd/toolchain-verify` — CLI (`check`, `init`, `version`).

## Possible next steps

`pin` subcommand that writes current versions/hashes into the manifest; env-var checks
(`GOFLAGS`, `NODE_OPTIONS`); signed manifests; GitHub Action wrapper.
