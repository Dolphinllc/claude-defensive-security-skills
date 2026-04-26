---
name: nextjs-security-scan
description: Defensive security scan for Next.js App Router projects. Detects environment-variable leakage to the browser bundle, unauthenticated server actions, missing middleware auth, unsafe CORS on route handlers, and trust-boundary violations in revalidatePath/revalidateTag. Invoke when the user asks to "review", "audit", or "scan" a Next.js codebase, or when editing files under app/ or middleware.ts.
---

# Next.js Security Scan

Performs a defensive security review of a Next.js App Router project (Next.js 13+). Reports findings using the [shared scoring schema](../../SCORING.md).

## Scope

Detects only — does not modify code. Targets:

- `app/**` — Server Components, Client Components, server actions, route handlers
- `middleware.ts` / `middleware.js`
- `next.config.{js,ts,mjs}`
- `.env*`

Out of scope: dependency CVEs (use `npm audit` / Snyk), runtime DAST.

## Procedure

1. Enumerate target files via `Glob`/`Grep`. Read each one once with `Read`.
2. Apply each rule in the table below. For every match, record a finding with severity, location, evidence, and fix.
3. Emit the final report in the schema from `SCORING.md`.

## Rules

| ID | Severity | Detection | Fix |
|----|----------|-----------|-----|
| NEXTJS-ENV-001 | critical | `process.env.NEXT_PUBLIC_*` referencing a secret-shaped name (`*_KEY`, `*_SECRET`, `*_TOKEN`, `*_PASSWORD`, `*_DSN`) | Remove `NEXT_PUBLIC_` prefix; access only in Server Components / route handlers |
| NEXTJS-ENV-002 | high | Secret-shaped env var read inside a file containing `"use client"` | Move read to a Server Component or route handler; pass derived non-secret value via props |
| NEXTJS-SA-001 | high | Exported `async function` in a `"use server"` file with no auth check (no call to `auth()`, `getServerSession`, `cookies()`-based check, or equivalent) before mutation | Add session check at the top of the action; return early on unauthenticated |
| NEXTJS-SA-002 | high | Server action accepts unvalidated `FormData`/object and passes fields directly to DB / fetch | Validate with `zod`/`valibot` schema before use |
| NEXTJS-MW-001 | high | `middleware.ts` has a `matcher` that excludes auth-sensitive routes (e.g., `/api/admin`, `/dashboard`) but no per-route check exists | Tighten `matcher` or add per-route guards |
| NEXTJS-MW-002 | medium | Middleware reads JWT but does not verify signature (`jwt.decode` instead of `jwt.verify` / `jose.jwtVerify`) | Use `jose.jwtVerify` with explicit `issuer`/`audience` |
| NEXTJS-RH-001 | high | `route.ts` returns response with `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true` | Pin origin to an allowlist; never combine wildcard with credentials |
| NEXTJS-RH-002 | medium | `route.ts` `POST`/`PUT`/`DELETE` handler reads `request.json()` without schema validation before persisting | Validate with `zod` before use |
| NEXTJS-RH-003 | medium | `route.ts` does not set `runtime` and uses Node-only crypto/secrets (risk of accidental Edge migration losing protections) | Add `export const runtime = 'nodejs'` explicitly |
| NEXTJS-REVAL-001 | medium | `revalidatePath` / `revalidateTag` called with a path/tag built from request input | Whitelist allowed paths; never interpolate user input |
| NEXTJS-IMG-001 | medium | `next.config` `images.remotePatterns` uses `**` host or omits `pathname` | Pin host and path prefix |
| NEXTJS-CSP-001 | medium | No `Content-Security-Policy` set in `middleware.ts` / `next.config` headers | Add CSP with nonce-based script-src |
| NEXTJS-DSI-001 | high | `dangerouslySetInnerHTML` with value not provably static (template literal, prop, state, fetched data) | Render as text, or sanitize with DOMPurify (server-side) |
| NEXTJS-LOG-001 | medium | `console.log` of `request.headers`, `cookies()`, `session`, or full `request.body` | Redact before logging; log IDs not payloads |

## Wrong vs. right

### NEXTJS-ENV-001 (env leak)

```ts
// ❌ Exposes the API key to every browser bundle
const key = process.env.NEXT_PUBLIC_ANTHROPIC_API_KEY;
```

```ts
// ✅ Server-only access
// app/api/chat/route.ts
export async function POST(req: Request) {
  const key = process.env.ANTHROPIC_API_KEY;
  // ...
}
```

### NEXTJS-SA-001 (unauth server action)

```ts
// ❌ Anyone who can hit the form can call this
"use server";
export async function deleteUser(id: string) {
  await db.user.delete({ where: { id } });
}
```

```ts
// ✅ Session-checked, schema-validated
"use server";
import { z } from "zod";
import { auth } from "@/auth";

const schema = z.object({ id: z.string().uuid() });

export async function deleteUser(input: unknown) {
  const session = await auth();
  if (!session?.user || session.user.role !== "admin") {
    throw new Error("Unauthorized");
  }
  const { id } = schema.parse(input);
  await db.user.delete({ where: { id } });
}
```

### NEXTJS-RH-001 (CORS + credentials)

```ts
// ❌ Browsers will reject this in modern versions, but older clients won't
return new Response(data, {
  headers: {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Credentials": "true",
  },
});
```

```ts
// ✅ Origin allowlist
const ALLOWED = new Set(["https://app.example.com"]);
const origin = req.headers.get("origin") ?? "";
const allow = ALLOWED.has(origin) ? origin : "";
return new Response(data, {
  headers: {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Credentials": "true",
    "Vary": "Origin",
  },
});
```

## References

- Next.js Server Actions: https://nextjs.org/docs/app/api-reference/functions/server-actions
- Next.js Middleware: https://nextjs.org/docs/app/building-your-application/routing/middleware
- Next.js Environment Variables: https://nextjs.org/docs/app/building-your-application/configuring/environment-variables
- OWASP CORS: https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny
