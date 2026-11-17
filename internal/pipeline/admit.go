package pipeline

import (
	"bufio"
	"os"
	"regexp"
	"strings"

	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

// AdmitInput is the process that would run the agent, before any tool call.
// AgentEnv is KEY=VALUE lines supplied by the operator. This package does
// not read /proc/*/environ. NetworkNone is nil when the agent network
// namespace was not stated; that is a fail, not a pass.
type AdmitInput struct {
	InContainer      bool
	RequireContainer bool
	CredPaths        []string
	GuardPaths       []string
	AgentEnv         []string
	NetworkNone      *bool
}

// Admit reports authority the process already has. An empty journal does
// not make these findings go away.
func Admit(in AdmitInput) []findings.Finding {
	var out []findings.Finding
	if in.RequireContainer && !in.InContainer {
		out = append(out, findings.Finding{
			Rule: "admit.container", Severity: findings.SevFail,
			Message: "require_container is set and this process is not in a container",
		})
	}
	for _, p := range in.CredPaths {
		if p == "" || !canRead(p) {
			continue
		}
		out = append(out, findings.Finding{
			Rule: "admit.credential", Severity: findings.SevFail, Path: p,
			Message: "agent uid can open a credential file",
		})
	}
	for _, p := range in.GuardPaths {
		if p == "" || !canWrite(p) {
			continue
		}
		out = append(out, findings.Finding{
			Rule: "admit.guard", Severity: findings.SevFail, Path: p,
			Message: "agent uid can write a hook or the exec policy",
		})
	}
	for _, line := range in.AgentEnv {
		key, val, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(val) == "" {
			continue
		}
		if secretNameRe.MatchString(key) || secretValueRe.MatchString(val) {
			out = append(out, findings.Finding{
				Rule: "admit.env", Severity: findings.SevFail, Path: key,
				Message: "agent environment contains a secret (name only)",
			})
		}
	}
	if in.NetworkNone == nil || !*in.NetworkNone {
		out = append(out, findings.Finding{
			Rule: "admit.network", Severity: findings.SevFail,
			Message: "agent network namespace is not none",
		})
	}
	return out
}

// ParseEnvFile reads KEY=VALUE lines. Values are returned to the caller and
// must not be written into a report.
func ParseEnvFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

func canRead(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func canWrite(path string) bool {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

var (
	secretNameRe  = regexp.MustCompile(`(?i)(token|secret|password|api[_-]?key|private[_-]?key|credential)`)
	secretValueRe = regexp.MustCompile(`AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|sk-[A-Za-z0-9]+|xox[baprs]-[A-Za-z0-9-]+`)
)
