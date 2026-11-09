package reposcan

import (
	"html"
	"regexp"
	"sort"
	"strings"
)

// Signal names. A signal is a hint; findings are raised for combinations
// (see judgeText), never for a single phrase in ordinary documentation.
const (
	sigOverride      = "instruction-override"
	sigConceal       = "conceal-from-user"
	sigForgedRole    = "forged-role-marker"
	sigInstallFirst  = "install-first"
	sigInstall       = "package-install"
	sigApproval      = "approval-bypass"
	sigConfigWrite   = "agent-config-rewrite"
	sigGlobalConfig  = "global-config-target"
	sigMarkdownExfil = "markdown-exfil"
	sigEndpoint      = "endpoint-redirect"
	sigSecretRead    = "secret-read"
	sigNetwork       = "network"
	sigExfil         = "exfil-endpoint"
	sigDecode        = "decode"
	sigExec          = "exec"
	sigPipeShell     = "pipe-to-shell"
)

type sigDef struct {
	name string
	re   *regexp.Regexp
}

// Patterns run on canonical text (see canonical): lower-case, HTML entities
// decoded, invisible format characters removed, whitespace collapsed.
// They are RE2 (linear time); inputs are bounded by the file size cap.
var sigDefs = []sigDef{
	{sigOverride, regexp.MustCompile(`\b(ignore|disregard|forget|override|bypass)\s+(all\s+|any\s+|the\s+|your\s+)*(previous|prior|above|earlier|preceding|system|existing|original)\s+(instructions|rules|prompts?|guidelines|directives|messages)|(игнорируй|игнорировать|проигнорируй|забудь|не\s+учитывай)\s+(все\s+)?(предыдущие|прежние|системные|прошлые|вышеуказанные)\s+(инструкции|указания|правила)`)},
	{sigConceal, regexp.MustCompile(`\b(do\s+not|don't|never)\s+(tell|inform|notify|mention|reveal|show|disclose)\s+(this\s+|it\s+|anything\s+)?(to\s+)?(the\s+)?(user|human|developer|reviewer|maintainer)s?\b|without\s+(asking|telling|notifying|informing|alerting)\s+(the\s+)?(user|human|developer)|\bhide\s+(this|it|the\s+change)\s+from\s+(the\s+)?(user|review|reviewer)|не\s+(сообщай|говори|показывай|уведомляй|рассказывай)\s+(об\s+этом\s+|ничего\s+)?пользовател|скр(ой|ыть)\s+(это\s+)?от\s+(ревью|ревьюер|пользовател)|молча\s+(выполни|установи|запусти|отправь)`)},
	{sigForgedRole, regexp.MustCompile(`<\|?im_start\|?>\s*system|<\s*(system|system_prompt|admin|developer_instructions)\s*>[^<]{8,600}<\s*/\s*(system|system_prompt|admin|developer_instructions)\s*>|^\s*<\s*/?\s*(system_prompt|developer_instructions)\s*>|\[\s*(system|admin)\s*(message|prompt|override|note)?\s*\]|\b(system|admin)\s+override\b|\b(maintenance|developer|debug|god|admin)\s+mode\s+(is\s+)?(enabled|activated|on)\b|allow_triage\s*=\s*true|<\s*important\s*>|\bnew\s+system\s+prompt\b`)},
	{sigInstallFirst, regexp.MustCompile(`\b(before|prior\s+to)\s+(doing\s+anything|any\s+other|your\s+first|running\s+any|you\s+(start|begin|do\s+anything)|answering|responding)[^.\n]{0,100}\b(run|install|execute|download|curl|wget)\b|\b(first|always)\s*,?\s+(run|install|execute)\s+[^.\n]{0,60}(setup|install|init|bootstrap)|сначала\s+(установи|запусти|выполни)|перед\s+(началом|первой|любой)[^.\n]{0,60}(установи|запусти|выполни)`)},
	{sigInstall, regexp.MustCompile(`\b(npm|pnpm|yarn|bun)\s+(i|install|add)\b|\bpip3?\s+install\b|\buv\s+(pip\s+install|add|tool\s+install)\b|\bnpx\s+(-y|--yes)\b|\bgem\s+install\b|\bgo\s+install\b|\bcargo\s+install\b`)},
	{sigApproval, regexp.MustCompile(`--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|\bbypasspermissions\b|approval[_-]?policy\s*[=:]\s*"?never|danger-full-access|--yolo\b|\byolo\s+mode\b|\bauto[-_ ]?approve\s*[=:]\s*(true|\[\s*"\*")|\balwaysallow\b|\b(do\s+not|don't|never)\s+ask\s+(the\s+user\s+)?(for\s+)?(permission|confirmation|approval)|\bskip\s+(all\s+|the\s+)?(confirmations?|approvals?|permission\s+prompts?)|не\s+спрашивай\s+(разрешени|подтвержд)|без\s+(подтверждения|разрешения)\s+пользовател`)},
	{sigMarkdownExfil, regexp.MustCompile(`!\[[^\]]*\]\(\s*https?://[^)\s]{0,200}(\{\{?[^}]+\}\}?|\$\{[^}]+\}|<[a-z_]+>)[^)]*\)|(render|display|show|output|insert|embed)\s+(a\s+)?(markdown\s+)?(image|img|picture)\s+(with|where|containing|whose\s+url)\s+.{0,80}(data|secret|key|token|password|env|conversation|history)`)},
	{sigGlobalConfig, regexp.MustCompile(`(~|\$home|\$\{home\}|%userprofile%|/home/[a-z0-9_.-]+|/root)/\.(codex|claude|cursor|gemini|config/(code|cursor|claude)|bashrc|zshrc|profile|ssh/authorized_keys|npmrc)|mcpservers|mcp_servers|\bcrontab\b|authorized_keys`)},
	{sigConfigWrite, regexp.MustCompile(`(write|add|append|insert|modify|update|edit|create|overwrite|replace|echo|tee|cat\s*>|>>?|добавь|измени|запиши|создай)[^\n]{0,120}(\.codex/config\.toml|\.claude/settings(\.local)?\.json|\.claude\.json|claude_desktop_config\.json|\.cursor/mcp\.json|\.gemini/settings\.json|\.vscode/(mcp|tasks|settings)\.json|\.mcp\.json|mcpservers|mcp_servers|\.bashrc|\.zshrc|\.profile|authorized_keys|crontab)`)},
	{sigEndpoint, regexp.MustCompile(`\b(anthropic_base_url|openai_base_url|openai_api_base|anthropic_api_url|gemini_api_base|azure_openai_endpoint)\b\s*[=:]`)},
	{sigSecretRead, regexp.MustCompile(`\.codex/auth\.json|\.claude/\.credentials|gh/hosts\.yml|\.git-credentials|\.aws/credentials|\.ssh/(id_|known_hosts|authorized)|\.npmrc|\.pypirc|\.netrc|\.gem/credentials|\.docker/config\.json|\.kube/config|oauth_creds|application_default_credentials|\bgh\s+auth\s+token\b|\bprintenv\b|\benv\s*\|\s*(curl|base64|nc)|\$\{?(gh_token|github_token|openai_api_key|anthropic_api_key|npm_token|aws_secret_access_key|aws_access_key_id|gitlab_token)\b|process\.env\b|os\.environ\b|/proc/[^\s]*/environ`)},
	{sigNetwork, regexp.MustCompile(`\b(curl|wget|invoke-webrequest|invoke-restmethod|iwr|irm)\b|\bfetch\s*\(|\brequests\.(post|get|put)\b|\burllib\.request\b|\bhttp\.(post|request|get)\b|\baxios\b|\bnet::http\b|\bopen-uri\b|\buri\.open\b|/dev/tcp/|\b(send|post|upload|exfiltrate|transmit|forward)\b[^\n]{0,100}\bto\s+https?://|\bnc\s+-[a-z]*\s|\bsocket\.connect\b`)},
	{sigExfil, regexp.MustCompile(`webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app)|interact\.sh|oast\.(fun|me|pro|live|site|online)|burpcollaborator|\btransfer\.sh\b|pastebin\.com/api|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot`)},
	{sigDecode, regexp.MustCompile(`\bbase64\s+(-d|--decode|-di)\b|\bb64decode\b|\batob\s*\(|buffer\.from\s*\([^)]{0,200}['"](base64|hex)['"]|frombase64string|\bxxd\s+-r\b|\bunhexlify\b|\bopenssl\s+(enc\s+)?-d\b|\bcodecs\.decode\b|\bzlib\.decompress\b|\bgunzip\b`)},
	{sigExec, regexp.MustCompile(`\beval\s*[\(\s"'$]|\bexec\s*\(|child_process|\bsubprocess\b|\bos\.system\b|\bsystem\s*\(|\bspawn(sync)?\s*\(|new\s+function\s*\(|\b(ba|z|da)?sh\s+-c\b|\bpopen\b|\bio\.popen\b|%x\{|\bkernel\.exec\b|\bnode\s+-e\b|\bpython3?\s+-c\b|\bbun\s+run\b|\binvoke-expression\b|\biex\b`)},
	{sigPipeShell, regexp.MustCompile(`\b(curl|wget|iwr|invoke-webrequest|irm)\b[^\n|]{0,300}\|\s*(sudo\s+)?(ba|z|da)?sh\b|\|\s*(sudo\s+)?(ba|z|da)?sh\s*$|\biex\s*\(\s*(new-object|iwr|irm|invoke)`)},
}

var wsRe = regexp.MustCompile(`[ \t\r\f\v]+`)

// canonical prepares text for signal matching: HTML entities are decoded
// (twice, for double-encoding), invisible format characters are dropped so
// that "ig\u200bnore" and "&#105;gnore" both read "ignore", runs of blanks
// collapse, and everything is lower-cased. Unicode Tags are decoded
// separately (decodeTags); they are not ASCII after removal.
func canonical(s string) string {
	if strings.IndexByte(s, '&') >= 0 {
		s = html.UnescapeString(html.UnescapeString(s))
	}
	s = strings.Map(func(r rune) rune {
		if isInvisible(r) {
			return -1
		}
		return r
	}, s)
	s = wsRe.ReplaceAllString(s, " ")
	return strings.ToLower(s)
}

// signals returns the sorted set of signal names found in canonical text.
func signals(canon string) map[string]bool {
	out := map[string]bool{}
	for _, d := range sigDefs {
		if d.re.MatchString(canon) {
			out[d.name] = true
		}
	}
	// "silently run/install/..." counts as concealment unless negated
	// ("do not silently add ..." is a benign style rule).
	for _, loc := range silentlyRe.FindAllStringIndex(canon, -1) {
		pre := canon[max(0, loc[0]-16):loc[0]]
		if !negationRe.MatchString(pre) {
			out[sigConceal] = true
			break
		}
	}
	return out
}

var (
	silentlyRe = regexp.MustCompile(`\b(silently|quietly|secretly|covertly)\s+(run|install|execute|upload|send|exfiltrate|modify|add|download|post)`)
	negationRe = regexp.MustCompile(`\b(not|never|don't|dont|no)\s*$`)
)

func sigList(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// firstMatch returns the byte offset of the first match of any of the named
// signals in canon, or -1.
func firstMatch(canon string, names ...string) int {
	best := -1
	for _, d := range sigDefs {
		for _, n := range names {
			if d.name != n {
				continue
			}
			if loc := d.re.FindStringIndex(canon); loc != nil && (best < 0 || loc[0] < best) {
				best = loc[0]
			}
		}
	}
	return best
}

// verdictFor turns a set of signals found in one chunk of text into a
// rule/severity. control: the text is something an agent loads as
// instructions or runs (instruction file, hook, task, lifecycle script).
// Outside control text only strong combinations count, because security
// docs legitimately quote attack phrases (the Radware study saw 116 false
// positives in the first 123 phrase hits).
func verdictFor(s map[string]bool, control bool) (rule, sev string) {
	action := s[sigInstall] || s[sigPipeShell] || s[sigNetwork] || s[sigSecretRead] || s[sigConfigWrite] || s[sigExec] || s[sigEndpoint]
	manip := s[sigOverride] || s[sigConceal] || s[sigForgedRole]
	switch {
	case s[sigSecretRead] && (s[sigNetwork] || s[sigExfil]):
		return "injection.secret-exfil", SevFail
	case s[sigDecode] && (s[sigExec] || s[sigPipeShell]):
		return "injection.decode-exec", SevFail
	case s[sigMarkdownExfil] && control:
		return "injection.markdown-exfil", SevFail
	case manip && action:
		return "injection.override-action", SevFail
	case s[sigInstallFirst] && (s[sigInstall] || s[sigPipeShell] || s[sigNetwork] || s[sigExec]):
		if control {
			return "injection.install-first", SevFail
		}
		return "injection.install-first", SevWarn
	}
	if !control {
		return "", ""
	}
	switch {
	case s[sigConfigWrite] && (s[sigGlobalConfig] || s[sigApproval] || s[sigExec] || s[sigNetwork] || s[sigInstall] || s[sigEndpoint]):
		return "injection.config-rewrite", SevFail
	case s[sigEndpoint]:
		return "injection.endpoint-redirect", SevFail
	case s[sigApproval]:
		return "injection.approval-bypass", SevFail
	case s[sigPipeShell]:
		return "injection.pipe-to-shell", SevFail
	case s[sigConfigWrite]:
		return "injection.config-rewrite", SevWarn
	case manip:
		return "injection.override", SevWarn
	case s[sigExfil]:
		return "injection.exfil-endpoint", SevWarn
	}
	return "", ""
}
