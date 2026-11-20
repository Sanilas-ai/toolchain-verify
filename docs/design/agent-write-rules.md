# Agent write rules (`scan`)

Three invariants for agents that call **write / mutating tools**: send, pay,
transfer, delete, publish, push. They come from Sanilas's request, relayed by
2T on 2026-11-16.

| Rule | Invariant | Static (manifest) | Heuristic (code) |
| --- | --- | --- | --- |
| `agent.write-policy-code-derived` | Code builds the admission policy for write tools from the tool schemas. It is never written by, or dependent on, a model's output. | **fail** unless `write_policy.source = "schema"` | warn: a policy/permission variable, or an `if` with allow/deny words, reads a value that comes from an LLM completion |
| `agent.write-plan-frozen-pre-untrusted` | The set of write actions is committed before the first read of tool output or other untrusted content, and never grows after it. | **fail** unless `write_plan.frozen_before_untrusted_read = true`; **fail** on `expand_after_untrusted = true` | warn: an append/extend/push to a plan collection (`plan`, `write_plan`, `planned_actions`, `pending_writes`, …) after the first tool-output / untrusted read in the file |
| `agent.write-args-from-user` | The who / what / how much / where of a write comes from the user request. Otherwise the agent refuses or a human confirms. | **fail** for a sensitive argument whose `source` is not `user` / `constant` / `schema` and that has no `human_confirm` on the argument or the tool | warn: a write call (`send_email(`, `transfer(`, `delete_*(`, `publish(`, …) receives a value derived from tool output with no confirmation call in the 15 lines before |

## Manifest

The scanner treats `agent-capabilities.toml`, `agent-capabilities.json`,
`agent-caps.toml` and `agent-caps.json` as control files: they are inventoried,
hashed and covered by `--baseline`. Full example:
[examples/agent-capabilities.toml](../../examples/agent-capabilities.toml).

```toml
schema = 1
agent = "mail-assistant"

[write_policy]
source = "schema"                      # schema | model | llm | prompt

[write_plan]
frozen_before_untrusted_read = true
expand_after_untrusted = false

[[tool]]
name = "send_email"
write = true                           # only write tools are checked
human_confirm = false                  # gates every argument of this tool
  [[tool.arg]]
  name = "to"
  role = "recipient"                   # recipient | content | amount | destination => sensitive
  source = "user"                      # user | constant | schema | tool_output | untrusted | model
  human_confirm = false
```

A manifest with no write tools gives one info finding. A manifest that does
not parse is a warning and makes the scan INCOMPLETE.

## Static, heuristic and future

- **Static (fail).** The manifest checks above. They check what the project
  *declares*, not what the code does. A wrong manifest passes. The value is that
  the invariant has to be stated, reviewed and diffed (`--baseline` notices
  when the manifest changes).
- **Heuristic (warn).** Only `.py/.js/.mjs/.cjs/.ts/.tsx/.go` files that
  contain an LLM client call are read. Files named `*_test.go`, `test_*`,
  `*.test.*`, `*.spec.*` and files under `testdata/` are skipped. The data flow
  is a single-file, line-order approximation:
  - names assigned from an LLM call or from a tool-output read propagate
    through later assignments that mention them;
  - there are no functions, no aliases and no loop back-edges;
  - "before" means an earlier line;
  - a gate is any confirmation-looking call in the 15 lines before the write.

  Expect both misses and false positives. Treat a hit as something to review.
- **Future (not implemented).**
  - Real data flow (SSA / tree-sitter, across functions and files).
  - Cross-checking the manifest against the code: tool names, whether
    `source = "schema"` really points to a schema-built table, and the MCP tool
    lists from `mcp-tools`.
  - Runtime enforcement in the tool-call gate (`toolcall`): plan commit and
    freeze, argument provenance tags, a human-confirmation hook.

## References (ideas only, no code taken)

- CapLite, [arXiv 2611.17115](https://arxiv.org/abs/2611.17115): when small models
  (1.7B–12B) wrote their own policies, 11–14 of 15 attacks got through. The
  rules encode the invariant; they do not rely on the paper's self-reported
  0 / 13 935 AgentDojo result, which we have not reproduced.
- Our earlier decisions (2026-11-10 … 13), which these rules complement:
  - a deterministic verifier decides on actions, not a model;
  - an injection gate plus taint tracking on tool output;
  - a capability-bound monitor that revokes injectable tools.
