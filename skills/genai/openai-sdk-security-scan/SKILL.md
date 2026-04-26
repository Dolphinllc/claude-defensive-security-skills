---
name: openai-sdk-security-scan
description: Defensive security scan for code using the OpenAI SDK (openai Python, openai Node). Detects API keys in client bundles, function-calling handlers without argument validation, missing structured-output schema, untrusted attachments fed to vision/Assistants, model output rendered as HTML, and verbose logging of full prompts. Invoke when the user asks to "review", "audit", or "scan" code that calls openai.chat.completions, responses, or assistants APIs.
---

# OpenAI SDK Security Scan

Defensive scan for applications using the OpenAI SDK. Reports findings using the [shared scoring schema](../../SCORING.md).

## Scope

- Files importing `openai` (Python) or `openai` (Node)
- Calls to `chat.completions.create`, `responses.create`, `beta.assistants.*`, `beta.threads.*`
- Function/tool definitions and dispatch handlers

## Rules

| ID | Severity | Detection | Fix |
|----|----------|-----------|-----|
| OAI-KEY-001 | critical | `new OpenAI({ apiKey: ... })` reads `NEXT_PUBLIC_*` / `VITE_*` / runs in client-side bundle | Move calls behind a server route; never ship the key |
| OAI-KEY-002 | high | Hardcoded `sk-...` key literal in source | Move to env; rotate immediately |
| OAI-INJ-001 | high | User-controlled document content in a `user` message without delimiter / data-vs-instruction framing | Wrap in tagged block (`<doc>...</doc>`) and instruct the model to treat as data |
| OAI-INJ-002 | high | Tool/function result returned to the model unsanitized while agent has high-privilege tools | Treat tool results as untrusted; require confirmation for irreversible actions |
| OAI-FN-001 | critical | Function-call handler executes shell / SQL / fs from `tool_calls[i].function.arguments` without parsing+validating against the declared `parameters` schema | Parse with `JSON.parse` then validate with zod/Pydantic against the same schema you advertised |
| OAI-FN-002 | high | Function declared with `additionalProperties: true` (or omitted) on input schema | Set `additionalProperties: false`; enumerate required fields |
| OAI-FN-003 | medium | Multiple high-impact tools registered without `tool_choice` constraints in agent loops | Constrain `tool_choice` per step; consider explicit per-step planner |
| OAI-OUT-001 | critical | Model output passed to `eval` / `exec` / `Function()` / `subprocess.run(shell=True)` / direct SQL | Parse into a structured schema and dispatch via allowlisted code paths |
| OAI-OUT-002 | high | Model output rendered with `dangerouslySetInnerHTML` / `v-html` / `innerHTML` | Render as text or sanitize |
| OAI-STRUCT-001 | medium | Code parses model output expecting JSON without using `response_format: { type: "json_schema", strict: true }` (or `response_format: { type: "json_object" }`) | Use Structured Outputs with strict schema; validate the result anyway |
| OAI-VISION-001 | high | Image URL in `image_url` content block fetched from user-supplied URL with no allowlist | Allowlist hosts; or download server-side, validate MIME/size, re-upload |
| OAI-ASST-001 | high | Assistants API thread shared across users (single thread id reused for many tenants) | One thread per user/session; never cross-tenant |
| OAI-ASST-002 | high | File uploaded via `files.create` from user input without size/MIME/AV check | Validate before upload; tag with tenant id |
| OAI-MOD-001 | medium | Output rendered in a public-facing UI without consulting `moderations` / safety classifier | Run user input through moderation for safety-critical surfaces; log decisions |
| OAI-LOG-001 | medium | Full `messages` / `input` / `output` logged at info level in production | Log request id and token counts; redact bodies |
| OAI-RETRY-001 | low | Custom retry loop without backoff on 429/5xx (DoS amplification) | Use SDK built-in retry or exponential backoff |

## Wrong vs. right

### OAI-FN-001 (unvalidated function args)

```python
# ❌ Direct execution
args = json.loads(tool_call.function.arguments)
subprocess.run(args["command"], shell=True)
```

```python
# ✅ Schema-validated + allowlisted
from pydantic import BaseModel
from typing import Literal

class RunArgs(BaseModel):
    command: Literal["build", "test", "lint"]

args = RunArgs.model_validate_json(tool_call.function.arguments)
spawn_allowlisted(args.command)
```

### OAI-STRUCT-001 (no structured output)

```ts
// ❌ Hope the model returns JSON
const completion = await client.chat.completions.create({
  model: "gpt-4.1",
  messages: [...],
});
const data = JSON.parse(completion.choices[0].message.content!);
```

```ts
// ✅ Strict schema enforcement
const completion = await client.chat.completions.create({
  model: "gpt-4.1",
  messages: [...],
  response_format: {
    type: "json_schema",
    json_schema: {
      name: "extract",
      strict: true,
      schema: {
        type: "object",
        additionalProperties: false,
        required: ["email", "score"],
        properties: {
          email: { type: "string", format: "email" },
          score: { type: "integer", minimum: 0, maximum: 100 },
        },
      },
    },
  },
});
```

### OAI-ASST-001 (cross-tenant thread)

```ts
// ❌ Single shared thread
const thread = await client.beta.threads.create();  // module-level
// later: every user posts to thread.id
```

```ts
// ✅ One thread per session
const threadId = await getOrCreateThreadForUser(userId);
```

## References

- OpenAI SDK (Node): https://github.com/openai/openai-node
- OpenAI SDK (Python): https://github.com/openai/openai-python
- Structured Outputs: https://platform.openai.com/docs/guides/structured-outputs
- Function calling: https://platform.openai.com/docs/guides/function-calling
- OWASP LLM Top 10: https://owasp.org/www-project-top-10-for-large-language-model-applications/
