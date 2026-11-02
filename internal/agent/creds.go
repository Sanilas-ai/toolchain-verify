package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// checkCredentials stats (never opens) well-known token/key files and
// reports loose permissions or foreign ownership.
func checkCredentials(r *resolved, c *collector) {
	var files []string
	for _, cf := range r.credFiles {
		if strings.ContainsAny(filepath.Base(cf), "*?[") {
			m, _ := filepath.Glob(cf)
			for _, f := range m {
				if !strings.HasSuffix(f, ".pub") {
					files = append(files, f)
				}
			}
			continue
		}
		files = append(files, cf)
	}
	for _, f := range files {
		st, err := os.Stat(f)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		mode := st.Mode().Perm()
		if mode&0o077 != 0 {
			sev := SevWarn
			if mode&0o004 != 0 || mode&0o002 != 0 {
				sev = SevFail
			}
			c.add(Finding{Rule: "cred.perms", Severity: sev, Path: f,
				Message: fmt.Sprintf("credential file is accessible to other users (%04o)", mode),
				Fix:     "chmod 600 " + f})
		}
		if uid, ok := fileUID(st); ok && r.uid >= 0 && uid != r.uid {
			c.add(Finding{Rule: "cred.owner", Severity: SevWarn, Path: f, Message: fmt.Sprintf("credential file owned by uid %d, not the current user", uid)})
		}
	}
	for _, d := range []string{filepath.Join(r.home, ".ssh"), filepath.Join(r.home, ".gnupg")} {
		if st, err := os.Stat(d); err == nil && st.IsDir() && st.Mode().Perm()&0o077 != 0 {
			c.add(Finding{Rule: "cred.perms", Severity: SevWarn, Path: d, Message: fmt.Sprintf("directory is accessible to other users (%04o)", st.Mode().Perm()), Fix: "chmod 700 " + d})
		}
	}
	// Tokens exported into the environment are inherited by every agent
	// tool call and by every MCP stdio server.
	var exposed []string
	for _, k := range []string{"GH_TOKEN", "GITHUB_TOKEN", "NPM_TOKEN", "AWS_SECRET_ACCESS_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "HF_TOKEN", "PYPI_TOKEN"} {
		if r.getenv(k) != "" {
			exposed = append(exposed, k)
		}
	}
	if len(exposed) > 0 {
		c.add(Finding{Rule: "cred.env", Severity: SevInfo,
			Message: "secrets exported in this environment (names only): " + strings.Join(exposed, ", ") + "; every agent tool call and stdio MCP server inherits them",
			Fix:     "pass credentials only to the specific tool that needs them (per-exec env), not to the agent session"})
	}
}
