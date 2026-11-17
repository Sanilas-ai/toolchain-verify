package pipeline

import (
	"path/filepath"
	"strings"

	"github.com/Sanilas-ai/toolchain-verify/internal/toolcall"
)

// BadArgument reports why args must not run. The returned string is a
// label ("a credential path", "a path outside trusted roots"), never the
// argument text. An empty trusted list skips the outside-root check.
// A calm tool name does not bypass this: the arguments are what is judged.
func BadArgument(args, home string, trusted []string) string {
	low := strings.ToLower(args)
	for _, frag := range []string{"/.ssh/", "/.gnupg/", "/.aws/", "auth.json", ".credentials.json", "/.config/gh/", "/.kube/", ".ssh/id_"} {
		if strings.Contains(low, frag) {
			return "a credential path"
		}
	}
	if len(trusted) == 0 {
		return ""
	}
	for _, field := range strings.Fields(args) {
		field = strings.Trim(field, `"'`)
		if field == "" || (!filepath.IsAbs(field) && !strings.HasPrefix(field, "~")) {
			continue
		}
		p := field
		if strings.HasPrefix(p, "~/") && home != "" {
			p = filepath.Join(home, p[2:])
		}
		p = filepath.Clean(p)
		inside := false
		for _, root := range trusted {
			root = filepath.Clean(root)
			if p == root || strings.HasPrefix(p, root+string(filepath.Separator)) {
				inside = true
				break
			}
		}
		if !inside {
			return "a path outside trusted roots"
		}
	}
	return ""
}

// ClassOf maps a tool name to a coarse class. "other" is not an allow.
func ClassOf(name string) string {
	n := strings.ToLower(name)
	switch {
	case n == "bash" || n == "shell" || strings.Contains(n, "shell") || n == "exec" || n == "powershell" || strings.Contains(n, "run_command") || n == "run_terminal_cmd":
		return "shell"
	case strings.Contains(n, "webfetch") || strings.Contains(n, "web_search") || strings.Contains(n, "websearch") || n == "fetch" || strings.Contains(n, "http") || strings.Contains(n, "browser"):
		return "untrusted"
	case strings.Contains(n, "send") || strings.Contains(n, "post") || strings.Contains(n, "comment") || strings.Contains(n, "email") || strings.Contains(n, "slack"):
		return "outbound"
	case strings.Contains(n, "write") || strings.Contains(n, "edit") || strings.Contains(n, "delete") || strings.Contains(n, "apply_patch"):
		return "write"
	case strings.Contains(n, "read") || strings.Contains(n, "grep") || strings.Contains(n, "glob"):
		return "path"
	default:
		return "other"
	}
}

// ScrubResult runs the tool-result scrub. rule is empty when the result
// may re-enter the context. The result text is not returned.
func ScrubResult(text string) (rule string) {
	rep := toolcall.Scrub(text)
	if rep.OK {
		return ""
	}
	if len(rep.Rules) > 0 {
		return rep.Rules[0]
	}
	return "toolcall.scrub"
}
