package reposcan

// Synthetic fixtures for the agent write rules. Files are generated into
// t.TempDir(); nothing is executed and no model is called.

import (
	"strings"
	"testing"
)

const badCaps = `schema = 1
agent = "mail-assistant"

[write_policy]
source = "model"          # the model writes its own allow list

[write_plan]
frozen_before_untrusted_read = false
expand_after_untrusted = true

[[tool]]
name = "read_inbox"

[[tool]]
name = "send_email"
write = true
  [[tool.arg]]
  name = "to"
  role = "recipient"
  source = "tool_output"
  [[tool.arg]]
  name = "body"
  role = "content"
  source = "model"

[[tool]]
name = "transfer"
write = true
  [[tool.arg]]
  name = "amount"
  role = "amount"
  [[tool.arg]]
  name = "memo"
  source = "tool_output"  # not sensitive
`

const goodCaps = `schema = 1
agent = "mail-assistant"

[write_policy]
source = "schema"

[write_plan]
frozen_before_untrusted_read = true

[[tool]]
name = "read_inbox"

[[tool]]
name = "send_email"
write = true
  [[tool.arg]]
  name = "to"
  role = "recipient"
  source = "user"
  [[tool.arg]]
  name = "body"
  role = "content"
  source = "tool_output"
  human_confirm = true

[[tool]]
name = "transfer"
write = true
human_confirm = true
  [[tool.arg]]
  name = "amount"
  role = "amount"
  source = "tool_output"
`

const badAgentPy = `import json
import requests
from openai import OpenAI

client = OpenAI()


def run(user_request):
    plan = []
    resp = client.chat.completions.create(model="m", messages=[{"role": "user", "content": "write a JSON allow list for the tools"}])
    policy = json.loads(resp.choices[0].message.content)
    page = requests.get(user_request.url).text
    for line in page.splitlines():
        plan.append({"tool": "send_email", "to": line})
    for step in plan:
        if step["tool"] in policy["allowed"]:
            send_email(to=page, body="hello")
`

const goodAgentPy = `import requests
from openai import OpenAI

from tools import TOOL_SCHEMAS, build_write_table, planner

client = OpenAI()
WRITE_TABLE = build_write_table(TOOL_SCHEMAS)


def run(user_request):
    steps = planner(user_request)  # committed before anything is read
    resp = client.chat.completions.create(model="m", messages=[{"role": "user", "content": user_request.text}])
    summary = resp.choices[0].message.content
    page = requests.get(user_request.url).text
    for step in steps:
        if step.tool in WRITE_TABLE:
            send_email(to=user_request.recipient, body=summary)
    if confirm_with_human(page):
        send_email(to=user_request.recipient, body=page)
`

func findAll(rep *Report, rule, sev string) []Finding {
	var out []Finding
	for _, f := range rep.Findings {
		if f.Rule == rule && (sev == "" || f.Severity == sev) {
			out = append(out, f)
		}
	}
	return out
}

func TestAgentWriteBad(t *testing.T) {
	root := t.TempDir()
	write(t, root, "agent/agent-capabilities.toml", badCaps)
	write(t, root, "agent/main.py", badAgentPy)
	rep := scan(t, root, Options{})
	if rep.Verdict != VerdictFail {
		t.Fatalf("verdict %s; %s", rep.Verdict, dump(rep))
	}
	for rule, want := range map[string]int{"agent.write-policy-code-derived": 1, "agent.write-plan-frozen-pre-untrusted": 2, "agent.write-args-from-user": 3} {
		got := findAll(rep, rule, SevFail)
		if len(got) != want {
			t.Errorf("%s: %d manifest failures, want %d; %s", rule, len(got), want, dump(rep))
		}
		for _, f := range got {
			if f.Path != "agent/agent-capabilities.toml" || len(f.Refs) == 0 {
				t.Errorf("%s: %+v", rule, f)
			}
		}
	}
	for _, f := range findAll(rep, "agent.write-args-from-user", SevFail) {
		if strings.Contains(f.Message, "memo") {
			t.Errorf("non-sensitive argument flagged: %s", f.Message)
		}
	}
	// heuristics on the code
	wantLines := map[string][]int{
		"agent.write-policy-code-derived":       {11, 16},
		"agent.write-plan-frozen-pre-untrusted": {14},
		"agent.write-args-from-user":            {17},
	}
	for rule, lines := range wantLines {
		got := findAll(rep, rule, SevWarn)
		if len(got) != len(lines) {
			t.Fatalf("%s: %d heuristic warnings, want %d; %s", rule, len(got), len(lines), dump(rep))
		}
		for i, f := range got {
			if f.Path != "agent/main.py" || f.Line != lines[i] || !strings.HasPrefix(f.Message, "heuristic: ") {
				t.Errorf("%s: %+v, want line %d", rule, f, lines[i])
			}
		}
	}
	found := false
	for _, c := range rep.Inventory {
		if c.Path == "agent/agent-capabilities.toml" && c.Kind == KindAgentCaps {
			found = true
		}
	}
	if !found {
		t.Errorf("manifest missing from the control-file inventory: %+v", rep.Inventory)
	}
}

func TestAgentWriteGood(t *testing.T) {
	root := t.TempDir()
	write(t, root, "agent/agent-capabilities.toml", goodCaps)
	write(t, root, "agent/main.py", goodAgentPy)
	quiet(t, scan(t, root, Options{}))
}

func TestAgentWriteJSONManifestAndEdges(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a/agent-capabilities.json", `{"schema":1,"tool":[{"name":"pay","write":true,"arg":[{"name":"iban","sensitive":true}]}]}`)
	write(t, root, "b/agent-caps.toml", "schema = 1\n[[tool]]\nname = \"search\"\n")
	rep := scan(t, root, Options{})
	if f := mustFind(t, rep, "agent.write-policy-code-derived", "a/agent-capabilities.json", SevFail); !strings.Contains(f.Message, "not declared") {
		t.Errorf("%s", f.Message)
	}
	if f := mustFind(t, rep, "agent.write-plan-frozen-pre-untrusted", "a/agent-capabilities.json", SevFail); !strings.Contains(f.Message, "not declared") {
		t.Errorf("%s", f.Message)
	}
	if f := mustFind(t, rep, "agent.write-args-from-user", "a/agent-capabilities.json", SevFail); !strings.Contains(f.Message, "iban has no declared source") {
		t.Errorf("%s", f.Message)
	}
	mustFind(t, rep, "agent.write-manifest", "b/agent-caps.toml", SevInfo)

	root = t.TempDir()
	write(t, root, "agent-capabilities.toml", "[write_policy\nsource=")
	rep = scan(t, root, Options{})
	mustFind(t, rep, "agent.write-manifest", "agent-capabilities.toml", SevWarn)
	if rep.Verdict == VerdictPass || len(rep.Coverage.Incomplete) == 0 {
		t.Errorf("unparsable manifest must not pass: %s %v", rep.Verdict, rep.Coverage.Incomplete)
	}
}

func TestAgentWriteHeuristicScope(t *testing.T) {
	root := t.TempDir()
	// No LLM call: the heuristics do not run.
	write(t, root, "plain.py", "import requests\nplan = []\npage = requests.get(u).text\nplan.append(page)\nsend_email(to=page)\n")
	// Tests and testdata are skipped.
	write(t, root, "test_agent.py", badAgentPy)
	write(t, root, "testdata/agent.py", badAgentPy)
	write(t, root, "agent.spec.ts", badAgentPy)
	quiet(t, scan(t, root, Options{}))

	// Go and TypeScript agents.
	root = t.TempDir()
	write(t, root, "agent.go", `package agent

func Run(ctx context.Context, req Request) error {
	resp, _ := client.CreateChatCompletion(ctx, chatReq(req))
	var plan []Action
	body := http.Get(req.URL)
	plan = append(plan, Action{To: body})
	return nil
}
`)
	write(t, root, "agent.ts", `const llm = new ChatModel();
const verdict = await llm.invoke(prompt);
const allowed = JSON.parse(verdict);
const page = await fetch(url);
await sendEmail(page);
transfer(page.amount);
`)
	rep := scan(t, root, Options{})
	mustFind(t, rep, "agent.write-plan-frozen-pre-untrusted", "agent.go", SevWarn)
	mustFind(t, rep, "agent.write-policy-code-derived", "agent.ts", SevWarn)
	mustFind(t, rep, "agent.write-args-from-user", "agent.ts", SevWarn)
}
