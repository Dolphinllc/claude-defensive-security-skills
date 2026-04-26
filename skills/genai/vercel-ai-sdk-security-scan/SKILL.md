---
name: vercel-ai-sdk-security-scan
description: Defensive security scan for the Vercel AI SDK (`ai` package). Detects unbounded experimental_attachments, streamText output rendered as HTML, tool execute handlers running shell from args, useChat endpoints without auth, generateObject schemas missing strict mode, and onFinish leaking content to telemetry. Invoke when the user asks to "review", "audit", or "scan" code using the AI SDK.
---

# Vercel AI SDK Security Scan

Defensive scan for code using the Vercel AI SDK (`ai`, `@ai-sdk/*`). Reports findings using the [shared scoring schema](../../SCORING.md).

## Scope

- Files importing `ai`, `@ai-sdk/openai`, `@ai-sdk/anthropic`, `@ai-sdk/google`, etc.
- Calls to `streamText`, `generateText`, `streamObject`, `generateObject`, `tool`, `convertToCoreMessages`
- Route handlers backing `useChat` / `useCompletion` / `useObject`

## Rules

| ID | Severity | Detection | Fix |
|----|----------|-----------|-----|
| VAI-KEY-001 | critical | Provider client (`createOpenAI`, `createAnthropic`, etc.) instantiated with API key in a file marked `"use client"` or under `app/` Client Component path | Initialize providers in route handlers / server actions only |
| VAI-AUTH-001 | high | Route handler backing `useChat` (`POST /api/chat`) has no auth check before calling `streamText` | Verify session/JWT at top of handler |
| VAI-TOOL-001 | critical | `tool({ ... execute: async (args) => { /* shell/sql/fs from args without validation */ } })` | Define `parameters: z.object(...)` and re-validate inside `execute`; allowlist values |
| VAI-TOOL-002 | high | Tool registered but `parameters` is `z.any()` / `z.object({}).passthrough()` | Define explicit zod schema with `.strict()` |
| VAI-OBJ-001 | medium | `generateObject` / `streamObject` called with a loose schema (`z.record`, `z.any`) | Use specific zod schema; rely on the SDK's enforcement |
| VAI-OUT-001 | high | `streamText` output piped to `dangerouslySetInnerHTML` (or markdown renderer with HTML enabled) on the client | Render as text or use a sanitizing markdown renderer (rehype-sanitize) |
| VAI-OUT-002 | critical | Server-side use of model output as code (`new Function`, `eval`, shell exec) | Never; parse into schema first |
| VAI-ATT-001 | high | `experimental_attachments` accepted from client without size / MIME / count limits | Validate on the server before forwarding to model |
| VAI-ATT-002 | medium | Attachments forwarded to model with URLs originating from arbitrary user input | Allowlist hosts; or download/validate server-side |
| VAI-INJ-001 | high | `system` prompt built by string-concatenating request data (e.g., user-provided role/persona) | Use parameterized templates with allowlisted values |
| VAI-INJ-002 | medium | RAG context passed inline without instruction-vs-data delimiters | Wrap retrieved chunks in tagged blocks; instruct model to treat as data |
| VAI-LOG-001 | medium | `onFinish({ text, usage, ... })` callback ships `text` to remote telemetry / 3rd-party logger | Log `usage`/`finishReason` only; redact text |
| VAI-RATE-001 | medium | `/api/chat` exposed without rate limiting | Apply per-user/IP limiter (Upstash / Vercel KV) |
| VAI-EDGE-001 | medium | Route uses `runtime: 'edge'` and reads Node-only secrets via `process.env` (works today but risk of build-time leakage if moved to client) | Mark `runtime = 'nodejs'` explicitly when using server-only secrets |

## Wrong vs. right

### VAI-TOOL-001 (unvalidated tool execute)

```ts
// ❌ Args go straight to shell
tools: {
  run: tool({
    description: 'Run a command',
    parameters: z.object({ cmd: z.string() }),
    execute: async ({ cmd }) => {
      const { stdout } = await execAsync(cmd);
      return stdout;
    },
  }),
}
```

```ts
// ✅ Allowlisted enum + dispatcher
tools: {
  run: tool({
    description: 'Run an allowlisted task',
    parameters: z.object({ task: z.enum(['build', 'test', 'lint']) }).strict(),
    execute: async ({ task }) => runAllowlisted(task),
  }),
}
```

### VAI-OUT-001 (HTML rendering)

```tsx
// ❌ Prompt-injection → XSS
<div dangerouslySetInnerHTML={{ __html: message.content }} />
```

```tsx
// ✅ Plain text or sanitized markdown
<ReactMarkdown
  remarkPlugins={[remarkGfm]}
  rehypePlugins={[rehypeSanitize]}>
  {message.content}
</ReactMarkdown>
```

### VAI-AUTH-001 (no auth on chat endpoint)

```ts
// ❌ Anyone with the URL gets to spend your tokens + access tools
export async function POST(req: Request) {
  const { messages } = await req.json();
  return streamText({ model, messages, tools }).toDataStreamResponse();
}
```

```ts
// ✅ Auth + per-tenant rate limit
export async function POST(req: Request) {
  const session = await auth();
  if (!session?.user) return new Response('Unauthorized', { status: 401 });
  const { success } = await ratelimit.limit(session.user.id);
  if (!success) return new Response('Too many requests', { status: 429 });
  const { messages } = await req.json();
  return streamText({ model, messages, tools, system: SYSTEM_PROMPT })
    .toDataStreamResponse();
}
```

## References

- Vercel AI SDK: https://sdk.vercel.ai/docs
- Tools and tool calling: https://sdk.vercel.ai/docs/foundations/tools
- Structured object generation: https://sdk.vercel.ai/docs/ai-sdk-core/generating-structured-data
