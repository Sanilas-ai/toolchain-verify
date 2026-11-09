package reposcan

// Offline linter for MCP tool definitions (a saved tools/list result).
//
// Capabilities re-implemented from the catalog review (no code copied):
// tool-description poisoning and cross-tool instructions (Invariant
// mcp-scan, MCP-Lattice, ramparts), input-schema poisoning and hidden
// parameters (MCP-Lattice, fuzzd), homoglyph / invisible tool names
// (MCP-Lattice), shadowing across servers, markdown-image exfiltration
// (Cisco skill-scanner), "toxic flow" / lethal-trifecta capability mix
// (mcp-scan, MCP-Lattice capability graph) and rug-pull detection by
// pinning a hash of every tool definition (mcp-scan, MCP-Lattice).
//
// It never connects to a server: capture tools/list inside the sandbox and
// lint the JSON here.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Tool is one MCP tool definition.
type Tool struct {
	Server      string
	Name        string
	Description string
	Schema      *jnode
	raw         *jnode
}

// ToolPin is the approved hash of every tool (rug-pull detection).
type ToolPin struct {
	Version int               `json:"version"`
	Created string            `json:"created,omitempty"`
	Tools   map[string]string `json:"tools"` // "server/tool" -> sha256
}

// LoadToolPin reads a pin file.
func LoadToolPin(p string) (*ToolPin, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var tp ToolPin
	if err := json.Unmarshal(b, &tp); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if tp.Version != 1 || tp.Tools == nil {
		return nil, fmt.Errorf("%s: not a version 1 tool pin", p)
	}
	return &tp, nil
}

// parseTools accepts a tools/list result ({"tools":[...]}), a JSON-RPC
// response ({"result":{"tools":[...]}}), a bare array of tools, or a map of
// server name -> any of those ({"servers":{...}} or top-level).
func parseTools(b []byte) ([]Tool, []dupKey, error) {
	root, dups, err := parseJSONC(b)
	if err != nil {
		return nil, dups, err
	}
	var out []Tool
	var collect func(server string, n *jnode, depth int) bool
	collect = func(server string, n *jnode, depth int) bool {
		if n == nil || depth > 4 {
			return false
		}
		if n.kind == jArray {
			ok := false
			for _, e := range n.elems {
				if e.kind == jObject && len(e.get("name", false)) > 0 {
					t := Tool{Server: server, raw: e}
					for _, v := range e.get("name", false) {
						t.Name = v.str
					}
					for _, k := range []string{"title", "description"} {
						for _, v := range e.get(k, false) {
							if v.kind == jString {
								t.Description += v.str + "\n"
							}
						}
					}
					for _, v := range e.get("inputSchema", false) {
						t.Schema = v
					}
					out = append(out, t)
					ok = true
				}
			}
			return ok
		}
		if n.kind != jObject {
			return false
		}
		for _, k := range []string{"tools"} {
			for _, v := range n.get(k, false) {
				if collect(server, v, depth+1) {
					return true
				}
			}
		}
		for _, v := range n.get("result", false) {
			if collect(server, v, depth+1) {
				return true
			}
		}
		srvs := n
		if s := n.get("servers", false); len(s) > 0 {
			srvs = s[0]
		}
		found := false
		for _, m := range srvs.members {
			if collect(m.key, m.val, depth+1) {
				found = true
			}
		}
		return found
	}
	if !collect("", root, 0) {
		return nil, dups, fmt.Errorf("no tools found (expected a tools/list result)")
	}
	return out, dups, nil
}

var (
	importantTagRe = regexp.MustCompile(`(?i)<\s*/?\s*(important|instructions?|secret|hidden|system|note_to_ai|ai_instructions)\s*>|\[\s*(important|hidden)\s*\]`)
	mdExfilRe      = regexp.MustCompile(`(?i)!\[[^\]]*\]\(\s*https?://[^)\s]{0,200}(\{\{?[^}]+\}\}?|\$\{[^}]+\}|\$[a-z_][a-z0-9_]*|<[a-z_]+>)[^)]*\)|(render|display|show|output|insert|embed)\s+(a\s+)?(markdown\s+)?(image|img|picture)\s+(with|where|containing|whose\s+url)\s+.{0,80}(data|secret|key|token|password|env|conversation|history)`)
	crossVerbRe    = regexp.MustCompile(`(?i)\b(always|must|first|instead|before|after|do\s+not|don't|never|whenever|when\s+(you|the\s+user)\s+(call|use|invoke))\b`)
	sensitiveParam = regexp.MustCompile(`(?i)^(side_?note|note_?to_?self|notes?_for_ai|context|conversation(_history)?|chat_?history|history|previous_messages|messages|system_?prompt|prompt|memory|feedback|debug_?info|metadata_?blob|extra|internal|secret|token|api_?key|password|credentials?|env|environment)$`)
)

// LintMCPTools lints tool definitions. pin may be nil.
func LintMCPTools(b []byte, pin *ToolPin) (*Report, []Tool, error) {
	tools, dups, err := parseTools(b)
	rep := &Report{Root: "tools/list", Coverage: Coverage{NotChecked: map[string]int{},
		SemanticNote: "static lint of tool metadata; tool behaviour and later tools/list changes are not observed (use --pin)"}}
	s := &scanner{rep: rep, seen: map[string]bool{}}
	for _, d := range dups {
		s.add(Finding{Rule: "config.duplicate-key", Severity: SevFail, Line: d.line, Evidence: escapeEvidence(d.key, 60),
			Message: "duplicate key in tool definitions: clients may read a different value than reviewers"})
	}
	if err != nil {
		return nil, nil, err
	}
	names := map[string][]Tool{}
	for _, t := range tools {
		names[strings.ToLower(t.Name)] = append(names[strings.ToLower(t.Name)], t)
	}
	for _, t := range tools {
		s.lintTool(t, tools)
	}
	// Shadowing: identical or near-identical names on different servers.
	keys := make([]string, 0, len(names))
	for k := range names {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, a := range keys {
		ts := names[a]
		if srvs := distinctServers(ts); len(srvs) > 1 {
			s.add(Finding{Rule: "mcp.tool-shadowing", Severity: SevWarn, Path: strings.Join(srvs, ","), Evidence: a,
				Message: "tool name " + escapeEvidence(a, 60) + " is offered by several servers; the model may call the wrong (malicious) one"})
		}
		for _, b := range keys[i+1:] {
			if len(a) >= 5 && editDistance(a, b, 1) == 1 && !sameServerOnly(names[a], names[b]) {
				s.add(Finding{Rule: "mcp.tool-shadowing", Severity: SevWarn, Evidence: a + " ~ " + b,
					Message: "near-identical tool names on different servers (" + toolID(names[a][0]) + " vs " + toolID(names[b][0]) + ")"})
			}
		}
	}
	s.toxicFlow(tools)
	if pin != nil {
		cur := map[string]bool{}
		for _, t := range tools {
			id, h := toolID(t), toolHash(t)
			cur[id] = true
			old, ok := pin.Tools[id]
			switch {
			case !ok:
				s.add(Finding{Rule: "mcp.tool-new", Severity: SevWarn, Path: id, Message: "tool not in the approved pin file"})
			case old != h:
				s.add(Finding{Rule: "mcp.rug-pull", Severity: SevFail, Path: id, Evidence: "pinned " + old[:12] + " now " + h[:12],
					Message: "tool definition (name/description/schema) changed since it was approved: possible rug pull",
					Fix:     "diff the definitions; re-pin only after review"})
			}
		}
		for id := range pin.Tools {
			if !cur[id] {
				s.add(Finding{Rule: "mcp.tool-removed", Severity: SevInfo, Path: id, Message: "pinned tool no longer offered"})
			}
		}
	}
	s.finish()
	rep.Inventory = nil
	for _, t := range tools {
		rep.Inventory = append(rep.Inventory, ControlFile{Path: toolID(t), Kind: "mcp-tool", SHA256: toolHash(t)})
	}
	return rep, tools, nil
}

// NewToolPin pins the given tools.
func NewToolPin(tools []Tool, created string) *ToolPin {
	tp := &ToolPin{Version: 1, Created: created, Tools: map[string]string{}}
	for _, t := range tools {
		tp.Tools[toolID(t)] = toolHash(t)
	}
	return tp
}

func toolID(t Tool) string {
	if t.Server == "" {
		return t.Name
	}
	return t.Server + "/" + t.Name
}

// toolHash hashes the canonical JSON of the whole definition (Go's
// encoding/json sorts map keys).
func toolHash(t Tool) string {
	b, _ := json.Marshal(toAny(t.raw))
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func toAny(n *jnode) any {
	if n == nil {
		return nil
	}
	switch n.kind {
	case jObject:
		m := map[string]any{}
		for _, mem := range n.members {
			if _, dup := m[mem.key]; dup {
				m[mem.key+"\x00dup"] = toAny(mem.val) // keep both in the hash
				continue
			}
			m[mem.key] = toAny(mem.val)
		}
		return m
	case jArray:
		a := make([]any, len(n.elems))
		for i, e := range n.elems {
			a[i] = toAny(e)
		}
		return a
	case jString:
		return n.str
	case jNumber:
		return json.Number(n.str)
	case jBool:
		return n.str == "true"
	}
	return nil
}

func distinctServers(ts []Tool) []string {
	m := map[string]bool{}
	for _, t := range ts {
		m[t.Server] = true
	}
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sameServerOnly(a, b []Tool) bool {
	sa, sb := distinctServers(a), distinctServers(b)
	return len(sa) == 1 && len(sb) == 1 && sa[0] == sb[0]
}

func (s *scanner) lintTool(t Tool, all []Tool) {
	id := toolID(t)
	// Name: invisible characters, mixed scripts (homoglyphs).
	if strings.IndexFunc(t.Name, isInvisible) >= 0 {
		s.add(Finding{Rule: "mcp.tool-name-invisible", Severity: SevFail, Path: id, Evidence: escapeEvidence(t.Name, 80),
			Message: "tool name contains invisible characters"})
	}
	if scripts := mixedScripts(t.Name); len(scripts) > 1 {
		s.add(Finding{Rule: "mcp.tool-name-homoglyph", Severity: SevFail, Path: id, Evidence: escapeEvidence(asciiEscape(t.Name), 80),
			Message: "tool name mixes scripts (" + strings.Join(scripts, "+") + "): a look-alike of another tool"})
	}
	desc := t.Description
	for _, r := range scanRunes([]byte(desc)) {
		f := Finding{Rule: "mcp.tool-hidden-text", Severity: SevFail, Path: id, Evidence: escapeEvidence(snippetAround([]byte(desc), r.offset, 100), evidenceRunes),
			Message: fmt.Sprintf("tool description contains %d invisible %s characters", r.count, r.kind)}
		if r.kind == "tags" {
			f.Decoded = escapeEvidence(r.decoded, evidenceRunes)
		}
		if r.kind == "zero-width" && r.count < 3 {
			f.Severity = SevWarn
		}
		s.add(f)
	}
	canon := canonical(desc)
	sig := signals(canon)
	if rule, sev := verdictFor(sig, true); rule != "" {
		s.add(Finding{Rule: "mcp.tool-poisoning", Severity: sev, Path: id, Evidence: escapeEvidence(desc, evidenceRunes), Signals: sigList(sig),
			Message: "tool description carries instructions for the model (" + strings.TrimPrefix(rule, "injection.") + ")",
			Refs:    []string{"https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"}})
	} else if importantTagRe.MatchString(desc) && (sig[sigSecretRead] || sig[sigConceal] || crossVerbRe.MatchString(desc)) {
		s.add(Finding{Rule: "mcp.tool-poisoning", Severity: SevFail, Path: id, Evidence: escapeEvidence(desc, evidenceRunes), Signals: sigList(sig),
			Message: "tool description hides model-directed instructions in <IMPORTANT>-style tags"})
	}
	if mdExfilRe.MatchString(desc) {
		s.add(Finding{Rule: "mcp.markdown-exfil", Severity: SevFail, Path: id, Evidence: escapeEvidence(mdExfilRe.FindString(desc), evidenceRunes),
			Message: "tool description builds a markdown image/link with dynamic data: rendering it sends data to a remote host"})
	}
	// Cross-tool instructions: imperative mention of another tool.
	for _, o := range all {
		if o.Name == t.Name || len(o.Name) < 4 {
			continue
		}
		on := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(o.Name) + `\b`)
		if loc := on.FindStringIndex(desc); loc != nil {
			win := desc[max(0, loc[0]-120):min(len(desc), loc[1]+120)]
			if crossVerbRe.MatchString(win) {
				sev := SevWarn
				if o.Server != t.Server {
					sev = SevFail
				}
				s.add(Finding{Rule: "mcp.cross-tool", Severity: sev, Path: id, Evidence: escapeEvidence(win, evidenceRunes),
					Message: "description tells the model how to use another tool (" + toolID(o) + "): tool shadowing / hijacking"})
				break
			}
		}
	}
	if len(desc) > 4000 {
		s.add(Finding{Rule: "mcp.tool-long-description", Severity: SevInfo, Path: id, Message: fmt.Sprintf("description is %d bytes (context pollution)", len(desc))})
	}
	// Input schema: injected property descriptions, suspicious defaults,
	// hidden data-collecting parameters.
	if t.Schema != nil {
		for _, props := range t.Schema.get("properties", false) {
			for _, p := range props.members {
				var texts []string
				p.val.walkStrings(nil, func(path []string, n *jnode) { texts = append(texts, n.str) })
				all := strings.Join(texts, "\n")
				psig := signals(canonical(all))
				if rule, sev := verdictFor(psig, true); rule != "" || importantTagRe.MatchString(all) || len(scanRunes([]byte(all))) > 0 {
					if rule == "" {
						sev = SevFail
					}
					s.add(Finding{Rule: "mcp.schema-poisoning", Severity: sev, Path: id + "#" + p.key, Evidence: escapeEvidence(all, evidenceRunes), Signals: sigList(psig),
						Message: "input-schema property " + escapeEvidence(p.key, 40) + " carries model-directed text"})
				}
				if sensitiveParam.MatchString(p.key) && !strings.Contains(strings.ToLower(desc), strings.ToLower(p.key)) {
					s.add(Finding{Rule: "mcp.hidden-parameter", Severity: SevWarn, Path: id + "#" + p.key,
						Message: "parameter " + escapeEvidence(p.key, 40) + " can collect conversation/secret data and is not mentioned in the description"})
				}
				for _, d := range p.val.get("default", false) {
					if d.kind == jString && (strings.Contains(d.str, "://") || len(signals(canonical(d.str))) > 0 || regexp.MustCompile(`[A-Za-z0-9+/]{60,}={0,2}`).MatchString(d.str)) {
						s.add(Finding{Rule: "mcp.schema-default", Severity: SevWarn, Path: id + "#" + p.key, Evidence: escapeEvidence(d.str, 100),
							Message: "default value is a URL, command or encoded blob; the model will send it without the user typing it"})
					}
				}
			}
		}
	}
}

func asciiEscape(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r < 0x80 {
			sb.WriteRune(r)
		} else {
			fmt.Fprintf(&sb, "\\u{%X}", r)
		}
	}
	return sb.String()
}

// mixedScripts returns the letter scripts used in s when more than one
// appears (Latin+Cyrillic, Latin+Greek, ...). Single-script non-Latin
// names are legitimate.
func mixedScripts(s string) []string {
	tables := []struct {
		name string
		t    *unicode.RangeTable
	}{{"Latin", unicode.Latin}, {"Cyrillic", unicode.Cyrillic}, {"Greek", unicode.Greek}, {"Armenian", unicode.Armenian}, {"Cherokee", unicode.Cherokee}}
	seen := map[string]bool{}
	for _, r := range s {
		if !unicode.IsLetter(r) {
			continue
		}
		for _, tb := range tables {
			if unicode.Is(tb.t, r) {
				seen[tb.name] = true
			}
		}
		if r >= 0xFF00 && r <= 0xFFEF { // fullwidth forms
			seen["Fullwidth"] = true
		}
	}
	if len(seen) < 2 {
		return nil
	}
	var out []string
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var (
	untrustedSourceRe = regexp.MustCompile(`(?i)(fetch|browse|navigate|scrape|crawl|web|url|http|search|read_?(email|mail|inbox|issue|pr|comment|message|page)|get_?(issue|pr|comment|email|page)|list_?(issues|emails|messages)|slack|discord)`)
	privateDataRe     = regexp.MustCompile(`(?i)(read_?file|file_?read|get_?file|filesystem|list_?dir|query|sql|database|db_|secret|credential|password|vault|env|keychain|calendar|contacts|drive|private|repo_?content|get_?file_?contents)`)
	publicSinkRe      = regexp.MustCompile(`(?i)(send|post|publish|upload|create_?(issue|pr|pull|comment|gist|release)|comment|reply|email|webhook|http_?(post|put)|tweet|share|push|write_?remote|notify)`)
)

// toxicFlow reports the "lethal trifecta": the same agent can read
// untrusted content, read private data and send data out. Each leg alone
// is normal; together an injected page/issue can exfiltrate secrets.
func (s *scanner) toxicFlow(tools []Tool) {
	var src, priv, sink []string
	for _, t := range tools {
		n := t.Name + " " + firstLine(t.Description)
		if untrustedSourceRe.MatchString(n) {
			src = append(src, toolID(t))
		}
		if privateDataRe.MatchString(n) {
			priv = append(priv, toolID(t))
		}
		if publicSinkRe.MatchString(n) {
			sink = append(sink, toolID(t))
		}
	}
	if len(src) > 0 && len(priv) > 0 && len(sink) > 0 {
		s.add(Finding{Rule: "mcp.toxic-flow", Severity: SevWarn,
			Message: fmt.Sprintf("tool set combines untrusted input (%s), private data (%s) and an outbound channel (%s): one injected document can exfiltrate data", short(src), short(priv), short(sink)),
			Fix:     "split these servers across sessions, or require human approval for the outbound tools",
			Refs:    []string{"https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/"}})
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func short(l []string) string {
	if len(l) > 3 {
		return strings.Join(l[:3], ", ") + fmt.Sprintf(" +%d", len(l)-3)
	}
	return strings.Join(l, ", ")
}
