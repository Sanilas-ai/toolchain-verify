# toolcall — safe parser for small local tool-call models

Small tool-call models (LFM3-1.7B, MiniCPM5-1B-Agentic-Tooluse-v3, …) often
**do not stop** after emitting a call. MiniCPM5-v3's own card reports
`stopped_cleanly_rate = 0.0000` and `no_repetition_rate = 0.3400` (claimed
numbers from the model card; not re-verified here). The runtime must therefore:

1. Take the **first complete, valid** tool call as the action.
2. Drop the rest of the generation (`trailing_junk`).
3. Feed the model stop sequences that match its chat template.
4. Validate JSON arguments against the tool schema.
5. Treat model output as **untrusted**.

## Commands

```bash
toolchain-verify toolcall profiles
toolchain-verify toolcall stops --profile minicpm5
toolchain-verify toolcall parse  --profile minicpm5 --tools tools.json [--approve|--no-tty] [--json] FILE
toolchain-verify toolcall bench  --profile minicpm5 --tools tools.json DIR [--runtime-note 'llama.cpp …']
toolchain-verify toolcall grounded [--source page.txt] FILE
```

## Confirmed formats (fetched 2026-11-09, data only)

| Profile | Format | Delimiters | Stop sequences | Sources |
|---------|--------|------------|----------------|---------|
| `lfm3` | XML (qwen3_coder-style) | `<tool_call><function=NAME><parameter=K>V</parameter></function></tool_call>` | `</tool_call>`, `<\|im_end\|>` | [Liquid tool-use docs](https://docs.liquid.ai/lfm/key-concepts/tool-use), [LFM3-1.7B chat_template.jinja](https://huggingface.co/LiquidAI/LFM3-1.7B/raw/main/chat_template.jinja) |
| `lfm2` | Pythonic list | `<\|tool_call_start\|>[fn(a="x")]<\|tool_call_end\|>` | `<\|tool_call_end\|>`, `<\|im_end\|>` | [LFM2-1.2B chat_template.jinja](https://huggingface.co/LiquidAI/LFM2-1.2B/raw/main/chat_template.jinja) |
| `minicpm5` | XML attrs | `<function name="N"><param name="K">V</param></function>` (CDATA for multiline) | `</function>`, `<\|im_end\|>` | [MiniCPM5 QLoRA-v3 chat_template.jinja](https://huggingface.co/ewin-reg/MiniCPM5-1B-Agentic-Tooluse-QLoRA-v3/raw/main/chat_template.jinja) |
| `hermes` | JSON in tags | `<tool_call>{"name":…,"arguments":{…}}</tool_call>` | `</tool_call>`, `<\|im_end\|>` | [vLLM hermes template](https://github.com/vllm-project/vllm/blob/main/examples/tool_chat_template_hermes.jinja) |

**Important:** LFM3 is **not** the LFM2 pythonic form. Liquid's docs say LFM3
switched to a qwen3_coder-style XML superset. Use `lfm3` for LFM3-1.7B and
`lfm2` only for LFM2 / LFM2.5.

For MiniCPM5 always call `apply_chat_template(..., enable_thinking=False)`.

## Security

- **Per-task tool allowlist.** Unknown names → `disallowed_tool` (never executed).
- **Description pin.** `description_sha256` rejects rug-pulled / MCP-poisoned
  tool descriptions (see arXiv 2611.03555; claimed 22.9% success — not verified here).
- **JSON Schema** subset: `type`, `properties`, `required`,
  `additionalProperties` (default **false**), `enum`, `items`, length/range.
- **Limits** on input size, argument size, nesting depth.
- **Hidden Unicode** (Tags U+E0000, bidi, zero-width) → rejected; stripped copy
  used only for diagnostics.
- **Exfil check** (`--exfil`, default on): `.env`-shaped dumps, PEM private
  keys, `AKIA…` / `ghp_…` patterns in arguments (Log-To-Leak via a fake logger).
- **Human gate** for classes `network`, `secrets`, `wallet`, `file_write`,
  `file_delete`, `shell`, `eval`, `env`: exact `yes` on `/dev/tty`, deny when
  there is no TTY (same idea as browser-control). No `.env` / secret access
  without that confirmation.
- Model output is never `eval`'d and never passed to a shell.

## Grounded search answers (Obsessive-1.7B pattern)

```
answer: …
quote: …
url: https://…
```

or the exact refusal string:

```
Not found in the search results
```

`--source` optionally checks that the quote appears **verbatim** in the
supplied page text (hallucination catch).

## Live bench (optional, skipped on this HP)

Before pulling or first-running any new local model on the HP, run
`toolchain-verify models` (and `agent` where appropriate). Run models only
inside Docker/sandbox.

This HP CPU has **no AVX**, so a stock llama.cpp build is not clearly feasible
here. LFM3 also needs llama.cpp ≥ b11960 (v0.8.0) / Ollama ≥ v0.40.12 (Linux
v0.40.13+); NVFP4 on older builds silently produces wrong output — always
record the runtime version in `--runtime-note`. Fixture `toolcall bench` is
the supported path until a compatible runtime exists.
