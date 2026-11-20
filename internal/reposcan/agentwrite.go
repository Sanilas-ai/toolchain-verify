package reposcan

// "agent write" rules: invariants for agents that call write / mutating
// tools (send, pay, transfer, delete, publish, ...). See
// docs/design/agent-write-rules.md.
//
//   - agent.write-policy-code-derived: the admission policy for write tools
//     is built by code from the tool schemas, never authored by a model.
//   - agent.write-plan-frozen-pre-untrusted: the set of write actions is
//     fixed before the first tool output / untrusted read and never grows.
//   - agent.write-args-from-user: recipient / content / amount / destination
//     come from the user request, or a human confirms them.
//
// Two layers. STATIC: an agent capability manifest (agent-capabilities.toml
// or .json) is checked; violations fail. HEURISTIC: agent source files
// (.py/.js/.ts/.go) that call an LLM client are read line by line with a
// tiny intra-file taint pass; matches warn. Nothing is executed.

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// KindAgentCaps is the agent capability manifest.
const KindAgentCaps = "agent-capabilities"

func isAgentCapsName(base string) bool {
	switch base {
	case "agent-capabilities.toml", "agent-capabilities.json", "agent-caps.toml", "agent-caps.json":
		return true
	}
	return false
}

// AgentCaps is the agent capability manifest.
type AgentCaps struct {
	Schema      int        `toml:"schema" json:"schema"`
	Agent       string     `toml:"agent" json:"agent"`
	WritePolicy *CapPolicy `toml:"write_policy" json:"write_policy"`
	WritePlan   *CapPlan   `toml:"write_plan" json:"write_plan"`
	Tools       []CapTool  `toml:"tool" json:"tool"`
}

// CapPolicy is [write_policy].
type CapPolicy struct {
	// Source: "schema" (code-derived from tool schemas) is the only
	// accepted value; "model", "llm", "prompt" are model-authored.
	Source string `toml:"source" json:"source"`
}

// CapPlan is [write_plan].
type CapPlan struct {
	FrozenBeforeUntrustedRead *bool `toml:"frozen_before_untrusted_read" json:"frozen_before_untrusted_read"`
	ExpandAfterUntrusted      bool  `toml:"expand_after_untrusted" json:"expand_after_untrusted"`
}

// CapTool is one [[tool]].
type CapTool struct {
	Name         string   `toml:"name" json:"name"`
	Write        bool     `toml:"write" json:"write"`
	HumanConfirm bool     `toml:"human_confirm" json:"human_confirm"`
	Args         []CapArg `toml:"arg" json:"arg"`
}

// CapArg is one [[tool.arg]].
type CapArg struct {
	Name string `toml:"name" json:"name"`
	// Role: recipient | content | amount | destination (each sensitive).
	Role      string `toml:"role" json:"role"`
	Sensitive bool   `toml:"sensitive" json:"sensitive"`
	// Source: user | constant | schema (trusted), or tool_output |
	// untrusted | model (need human_confirm).
	Source       string `toml:"source" json:"source"`
	HumanConfirm bool   `toml:"human_confirm" json:"human_confirm"`
}

var (
	sensitiveRoles    = map[string]bool{"recipient": true, "content": true, "amount": true, "destination": true}
	trustedArgSources = map[string]bool{"user": true, "constant": true, "schema": true}
	capLiteRefs       = []string{"https://arxiv.org/abs/2611.17115"}
	writeRuleCWE      = []string{"CWE-1426", "CWE-863"}
)

func (s *scanner) scanAgentCaps(rel string, b []byte) {
	var m AgentCaps
	var err error
	if strings.HasSuffix(strings.ToLower(rel), ".json") {
		err = json.Unmarshal(b, &m)
	} else {
		_, err = toml.Decode(string(b), &m)
	}
	if err != nil {
		s.incomplete(rel + ": agent capability manifest does not parse")
		s.add(Finding{Rule: "agent.write-manifest", Severity: SevWarn, Path: rel, Message: "agent capability manifest does not parse: " + err.Error()})
		return
	}
	var names []string
	var writes []CapTool
	for _, t := range m.Tools {
		if t.Write {
			writes = append(writes, t)
			names = append(names, t.Name)
		}
	}
	if len(writes) == 0 {
		s.add(Finding{Rule: "agent.write-manifest", Severity: SevInfo, Path: rel, Message: "manifest declares no write tools; agent write rules do not apply"})
		return
	}
	wt := strings.Join(names, ", ")
	fail := func(rule, msg, fix string) {
		s.add(Finding{Rule: rule, Severity: SevFail, Path: rel, CWE: writeRuleCWE, Message: msg, Fix: fix, Refs: capLiteRefs})
	}

	// 1. the write admission policy is code-derived
	src := ""
	if m.WritePolicy != nil {
		src = strings.ToLower(strings.TrimSpace(m.WritePolicy.Source))
	}
	switch src {
	case "schema":
	case "":
		fail("agent.write-policy-code-derived",
			"write tools ("+wt+") but write_policy.source is not declared; the admission policy for write tools must be built by code from the tool schemas",
			`build the write-tool allow table in code from the tool schemas and declare [write_policy] source = "schema"`)
	default:
		fail("agent.write-policy-code-derived",
			fmt.Sprintf("write_policy.source = %q: the admission policy for write tools (%s) is not derived from the tool schemas; model-authored policies let most attacks through on small models", src, wt),
			`generate the policy deterministically from the tool schemas (source = "schema"); never accept a policy the model wrote`)
	}

	// 2. the write plan is frozen before the first untrusted read
	switch {
	case m.WritePlan == nil || m.WritePlan.FrozenBeforeUntrustedRead == nil:
		fail("agent.write-plan-frozen-pre-untrusted",
			"write_plan.frozen_before_untrusted_read is not declared; the set of write actions must be committed before the first tool output or untrusted content is read",
			"commit the write plan before any tool output is read and declare [write_plan] frozen_before_untrusted_read = true")
	case !*m.WritePlan.FrozenBeforeUntrustedRead:
		fail("agent.write-plan-frozen-pre-untrusted",
			"write_plan.frozen_before_untrusted_read = false: tool output or untrusted content can add write actions (an injection picks the next write)",
			"freeze the write plan before the first untrusted read")
	}
	if m.WritePlan != nil && m.WritePlan.ExpandAfterUntrusted {
		fail("agent.write-plan-frozen-pre-untrusted",
			"write_plan.expand_after_untrusted = true: the write plan may grow after untrusted content was read",
			"never extend the write plan after an untrusted read; ask the user in a new turn instead")
	}

	// 3. who / what / how much / where come from the user or a human gate
	for _, t := range writes {
		for _, a := range t.Args {
			role := strings.ToLower(strings.TrimSpace(a.Role))
			if !a.Sensitive && !sensitiveRoles[role] {
				continue
			}
			as := strings.ToLower(strings.TrimSpace(a.Source))
			if trustedArgSources[as] || a.HumanConfirm || t.HumanConfirm {
				continue
			}
			what := a.Name
			if role != "" {
				what += " (" + role + ")"
			}
			why := fmt.Sprintf("comes from %q", as)
			if as == "" {
				why = "has no declared source"
			}
			fail("agent.write-args-from-user",
				fmt.Sprintf("write tool %s: argument %s %s and has no human_confirm gate; who / what / how much / where must come from the user request", t.Name, what, why),
				`take the value verbatim from the user request (source = "user") or set human_confirm = true on the argument or the tool`)
		}
	}
}

// ---- heuristics over agent source code ----

var (
	agentSrcExt = map[string]bool{".py": true, ".js": true, ".mjs": true, ".cjs": true, ".ts": true, ".tsx": true, ".go": true}
	// An LLM client call; files without one are skipped.
	llmCallRe = regexp.MustCompile(`(?i)(\.chat\.completions\.create\(|\.completions\.create\(|\.messages\.create\(|\.responses\.create\(|generate_?content\(|ChatCompletion\.create\(|\bllm\.(invoke|predict|complete|generate)\(|\bmodel\.(invoke|generate_content)\(|\bollama\.(chat|generate)\(|\bcompletion\(\s*model\s*=|CreateChatCompletion\(|\.Messages\.New\()`)
	// Reads of tool output or untrusted content.
	taintSrcRe  = regexp.MustCompile(`(?i)(\btool_?(output|result)s?\b|\bfunction_call_output\b|\bobservation\b|\brequests\.(get|post)\(|\burlopen\(|\bfetch\(|\bhttp\.Get\(|\bread_?file\(|\bReadFile\(|\bweb_?search\(|\bbrowse\(|\bget_?url\(|\buntrusted\b|\bemail_?body\b|\binbox\b|\bissue\.body\b|\bcomment\.body\b)`)
	assignRe    = regexp.MustCompile(`^\s*(?:(?:const|let|var)\s+)?([A-Za-z_]\w*)\s*(?::=|=)\s*(.*)$`)
	policyRe    = regexp.MustCompile(`(?i)(allow|deny|denied|permit|authori[sz]|approv|polic|is_?safe|admit)`)
	planNames   = `write_?plan|planned_?(?:actions|writes|calls)|write_?actions|pending_?writes|action_?plan|plan`
	planRe      = regexp.MustCompile(`(?i)\b(?:` + planNames + `)\s*(?:\.(?:append|extend|push|add|insert|concat|unshift)\(|\+=)|=\s*append\(\s*(?:` + planNames + `)\b`)
	writeCallRe = regexp.MustCompile(`(?i)\b(?:send_?(?:email|mail|message|money|payment|funds)|transfer(?:_?funds)?|make_?payment|wire_?funds|withdraw|delete_?\w+|post_?(?:message|comment|tweet)|create_?(?:issue|pull_?request|pr)|publish|push_?to|write_?file|execute_?write|SendEmail|Transfer)\s*\(`)
	confirmRe   = regexp.MustCompile(`(?i)(human_?confirm|confirm\w*\(|require_?approval|ask_?user|\binput\(|interrupt\(|approve\w*\(|human_in_the_loop|await_?approval)`)
	identRe     = regexp.MustCompile(`[A-Za-z_]\w*`)
)

func isAgentSource(rel string) bool {
	l := strings.ToLower(rel)
	if !agentSrcExt[path.Ext(l)] {
		return false
	}
	base := path.Base(l)
	return !(strings.HasSuffix(base, "_test.go") || strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") ||
		strings.HasPrefix(base, "test_") || strings.Contains("/"+l, "/testdata/"))
}

func mentions(expr string, vars map[string]bool) string {
	for _, id := range identRe.FindAllString(expr, -1) {
		if vars[id] {
			return id
		}
	}
	return ""
}

// scanAgentWriteCode is a line-order, single-file approximation of data
// flow: names assigned from an LLM call (llm) or from tool output (taint)
// propagate through later assignments that mention them.
func (s *scanner) scanAgentWriteCode(rel string, b []byte) {
	text := string(b)
	if !llmCallRe.MatchString(text) {
		return
	}
	lines := strings.Split(text, "\n")
	llm, taint := map[string]bool{}, map[string]bool{}
	firstTaint := 0
	type hit struct {
		rule, msg, ev string
		line          int
	}
	var hits []hit
	for i, ln := range lines {
		no := i + 1
		code := strings.TrimSpace(ln)
		if code == "" || strings.HasPrefix(code, "#") || strings.HasPrefix(code, "//") {
			continue
		}
		if firstTaint == 0 && taintSrcRe.MatchString(code) {
			firstTaint = no
		}
		if m := assignRe.FindStringSubmatch(ln); m != nil && !strings.HasPrefix(m[2], "=") {
			lhs, rhs := m[1], m[2]
			if llmCallRe.MatchString(rhs) || mentions(rhs, llm) != "" {
				llm[lhs] = true
				if policyRe.MatchString(lhs) {
					hits = append(hits, hit{"agent.write-policy-code-derived", lhs + " (a policy / permission value) is computed from an LLM completion", code, no})
				}
			}
			if taintSrcRe.MatchString(rhs) || mentions(rhs, taint) != "" {
				taint[lhs] = true
			}
		}
		if strings.HasPrefix(code, "if ") || strings.HasPrefix(code, "if(") || strings.HasPrefix(code, "elif ") || strings.HasPrefix(code, "} else if") {
			if v := mentions(code, llm); v != "" && policyRe.MatchString(code) {
				hits = append(hits, hit{"agent.write-policy-code-derived", "an allow/deny decision reads " + v + ", which comes from an LLM completion", code, no})
			}
		}
		if firstTaint > 0 && planRe.MatchString(code) {
			hits = append(hits, hit{"agent.write-plan-frozen-pre-untrusted", fmt.Sprintf("the write plan is extended after the first tool-output / untrusted read (line %d)", firstTaint), code, no})
		}
		if loc := writeCallRe.FindStringIndex(code); loc != nil {
			args := code[loc[1]:]
			v := mentions(args, taint)
			if v == "" && !taintSrcRe.MatchString(args) {
				continue
			}
			gated := false
			for j := i; j >= 0 && j >= i-15; j-- {
				if confirmRe.MatchString(lines[j]) {
					gated = true
					break
				}
			}
			if !gated {
				if v == "" {
					v = "tool output"
				}
				hits = append(hits, hit{"agent.write-args-from-user", "a write-call argument comes from " + v + " (tool output / untrusted content) with no human-confirm gate in the 15 lines before", code, no})
			}
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].line < hits[j].line })
	for _, h := range hits {
		s.add(Finding{Rule: h.rule, Severity: SevWarn, Path: rel, Line: h.line, Evidence: escapeEvidence(h.ev, 100), CWE: []string{"CWE-1426"},
			Message: "heuristic: " + h.msg,
			Fix:     "see docs/design/agent-write-rules.md; declare the agent in agent-capabilities.toml so the static rules apply",
			Refs:    capLiteRefs})
	}
}
