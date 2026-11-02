# Contributing

Thanks for helping! Small, focused pull requests are easiest to review.

1. Open an issue first for anything bigger than a bug fix.
2. Keep the dependency footprint minimal (currently only `github.com/BurntSushi/toml`).
   This is a security-oriented tool; every new dependency needs a good reason.
3. Before sending a PR:
   ```bash
   gofmt -l .        # must print nothing
   go vet ./...
   go test ./...
   ```
4. Add tests for new constraint syntax, manifest keys, or check behaviour.
5. Use clear commit messages (Conventional Commits welcome: `feat:`, `fix:`, `docs:`).
6. Advisory DB (`internal/agent/advisories.toml`): every entry must cite a primary
   source (GitHub Security Advisory, NVD, vendor bulletin) in `refs`. Never invent or
   guess GHSA/CVE IDs or version ranges; if the fix is unconfirmed or the issue needs a
   specific configuration, use `action = "warn"`. Bump `updated` and add a test case.
7. By contributing you agree your work is licensed under Apache-2.0.

Security issues: please do not open a public issue; use GitHub's
"Report a vulnerability" (private advisory) on this repository instead.
