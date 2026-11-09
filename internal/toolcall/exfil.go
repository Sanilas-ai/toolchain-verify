package toolcall

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	reEnvLine = regexp.MustCompile(`(?m)^(?:export\s+)?[A-Z][A-Z0-9_]{2,}=.+$`)
	rePEM     = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)
	reAWS     = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	reGitHub  = regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`)
)

// detectExfil walks string arguments looking for .env dumps / key material
// that a fake "logger" tool might be trying to ship out (Log-To-Leak).
func detectExfil(args map[string]interface{}) string {
	var hit string
	walk(args, func(path string, s string) {
		if hit != "" {
			return
		}
		low := strings.ToLower(path)
		if strings.Contains(low, "password") || strings.Contains(low, "secret") || strings.Contains(low, "private_key") {
			if len(s) > 0 {
				hit = path + ": sensitive field name with non-empty value"
				return
			}
		}
		if rePEM.MatchString(s) {
			hit = path + ": private key PEM"
			return
		}
		if reAWS.MatchString(s) || reGitHub.MatchString(s) {
			hit = path + ": cloud/token pattern"
			return
		}
		if strings.Count(s, "\n") >= 2 && len(reEnvLine.FindAllString(s, -1)) >= 3 {
			hit = path + ": looks like .env dump"
			return
		}
		if strings.Contains(s, "OPENAI_API_KEY=") || strings.Contains(s, "AWS_SECRET_ACCESS_KEY=") {
			hit = path + ": known secret env assignment"
			return
		}
	})
	return hit
}

func walk(v interface{}, fn func(path, s string)) {
	walkPath(v, "$", fn)
}

func walkPath(v interface{}, path string, fn func(path, s string)) {
	switch t := v.(type) {
	case string:
		fn(path, t)
	case map[string]interface{}:
		for k, vv := range t {
			walkPath(vv, path+"."+k, fn)
		}
	case []interface{}:
		for i, vv := range t {
			walkPath(vv, fmt.Sprintf("%s[%d]", path, i), fn)
		}
	}
}
