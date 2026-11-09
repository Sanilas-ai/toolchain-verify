package reposcan

import "regexp"

// secretRe matches common credential formats. Used to redact evidence and
// to flag secrets stored in agent settings (e.g. Claude Code "don't ask
// again" permission rules that captured a token; THN/Apiiro, Nov 2026).
var secretRe = regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|glpat-[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-(proj-)?[A-Za-z0-9_-]{32,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[abprs]-[A-Za-z0-9-]{10,}|npm_[A-Za-z0-9]{36}|AIza[0-9A-Za-z_-]{35}|hf_[A-Za-z0-9]{30,}|pypi-[A-Za-z0-9_-]{50,}|rubygems_[a-f0-9]{48}|sk_live_[0-9A-Za-z]{24,}|rk_live_[0-9A-Za-z]{24,}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}|ya29\.[0-9A-Za-z_-]{20,}|xapp-[0-9A-Za-z-]{20,}|dop_v1_[a-f0-9]{64}|shpat_[a-fA-F0-9]{32}|[0-9]{8,10}:AA[A-Za-z0-9_-]{33})\b|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?i)\b(authorization:\s*(bearer|token|basic)\s+)[A-Za-z0-9._~+/=-]{16,}`)

// redact replaces secrets with their first 4 characters and a marker.
func redact(s string) string {
	return secretRe.ReplaceAllStringFunc(s, func(m string) string {
		if len(m) <= 8 {
			return "[redacted]"
		}
		return m[:4] + "…[redacted]"
	})
}

func hasSecret(s string) bool { return secretRe.MatchString(s) }
