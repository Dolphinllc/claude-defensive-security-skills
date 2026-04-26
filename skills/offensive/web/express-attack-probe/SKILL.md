---
name: express-attack-probe
description: Authorized self-pentest probe targeting Express.js-specific weaknesses. Tests prototype pollution via merge/clone middlewares, HPP (HTTP parameter pollution) via body-parser, x-forwarded-for spoofing when trust proxy is loose, qs depth/array bombs, sendFile path traversal, and known unsafe middleware patterns. Use when the user asks to "pentest" or "attack-test" their own Express app.
---

# Express Attack Probe

Authorized probe of an Express.js app the user owns. Follow [shared probing conventions](../../../PROBING.md) — discover base URL via env / `package.json` `scripts.dev` / `Dockerfile`. Never hardcode the port.

## Express-specific attack surface

- **Middleware order** is silently security-critical: routes registered before auth bypass it entirely.
- **`req.body` is `Object`-prototype-mergeable** in apps using `lodash.merge` / `Object.assign(target, req.body)` — prototype pollution → privilege escalation when the merged object is later checked for `isAdmin`.
- **`qs` (default Express query parser)** parses `?a[b][c]=1` into nested objects up to depth 5; can cause CPU bombs and bypass naive type checks.
- **`trust proxy` set to `true`** lets attackers spoof `req.ip` / `X-Forwarded-For`, defeating per-IP rate-limit / geo-block.
- **`res.sendFile` / `res.download`** without containment leaks files outside the intended root.

## Procedure

1. Authorization preflight + base URL discovery.
2. Identify routes (parse `app.use`/`app.get`/`router.*` in source if available, else crawl).
3. Probe per the rule table; stop at request budget.

## Rules

| ID | Severity (if confirmed) | Probe | Confirmed when |
|----|------|-------|----------------|
| EXP-PP-001 | high | `POST` JSON body with `{"__proto__": {"isAdmin": true}}` to any update/profile endpoint, then make an authenticated read | A subsequent normal-user response shows admin-only data / privileged flag |
| EXP-PP-002 | medium | Same body with `{"constructor": {"prototype": {"polluted": 1}}}`, then probe an endpoint that reflects an object key | Response contains `polluted` |
| EXP-HPP-001 | medium | `POST` form `a=1&a=2&a=3` to a route that uses `req.body.a` as a string | Server logs / response treats `a` as array, indicating type-confusion bug |
| EXP-QS-001 | medium | `GET /?a[b][c][d][e][f]=1` (depth bomb) | 500 / OOM signal — Express's default `qs` allows depth 5 but apps mutate it |
| EXP-QS-002 | low | `GET /?a[]=1&a[]=2&...` (1000 entries) — keep below DoS threshold per `PROBING.md` (≤200 reqs total) | App accepts and processes; combined with mass-assign = high |
| EXP-PROXY-001 | high | Send `X-Forwarded-For: 1.2.3.4` to `/login` or rate-limited endpoint, repeat with rotating values | Each request counted as different IP = `trust proxy = true` |
| EXP-ORDER-001 | critical | Identify a sensitive route (`/admin`, `/api/users/{id}`) and call without auth headers | 2xx response identical to authenticated = auth registered after route |
| EXP-SF-001 | high | If a file-serving route exists (`GET /files/:name`), request `GET /files/..%2F..%2Fpackage.json` and `/files/..%2F..%2F.env` | Response body matches the file = path traversal in `sendFile` |
| EXP-CORS-001 | high | `OPTIONS /api/*` with `Origin: https://evil.test` + credentials | `ACAO: https://evil.test` AND `ACAC: true` reflected = `cors({origin: true, credentials: true})` |
| EXP-JWT-001 | high | If JWT-based: send `Authorization: Bearer <alg=none token>` and `<HS256 with public key as secret>` | 2xx accepted = `jwt.verify` without `algorithms` option |
| EXP-EH-001 | medium | Trigger an error (`POST /api/x` with malformed JSON, very long string, type confusion) | 500 response leaks stack trace mentioning file paths / `node_modules` |
| EXP-SESS-001 | medium | Login, capture `connect.sid`. Re-fix the same SID before second login attempt; check if accepted | Session ID not regenerated on login = fixation |

## Wrong vs. right (defenses confirmed by these probes)

### EXP-PP-001 (prototype pollution)

```js
// ❌
app.patch('/me', (req, res) => {
  Object.assign(req.user, req.body);     // pollutes Object.prototype
  res.json(req.user);
});
```

```js
// ✅
const ALLOWED = ['name', 'email', 'avatar'];
app.patch('/me', (req, res) => {
  const updates = Object.fromEntries(
    ALLOWED.filter(k => k in req.body).map(k => [k, req.body[k]])
  );
  Object.assign(req.user, updates);
  res.json(req.user);
});
```

### EXP-PROXY-001 (loose trust proxy)

```js
// ❌
app.set('trust proxy', true);            // any client can spoof X-Forwarded-For
app.use(rateLimit({ keyGenerator: req => req.ip }));
```

```js
// ✅
app.set('trust proxy', 1);               // exactly one hop = your LB
// or: app.set('trust proxy', 'loopback, 10.0.0.0/8');
```

## References

- OWASP Cheat Sheet — Node.js: https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html
- Prototype pollution: https://learn.snyk.io/lesson/prototype-pollution/
- Express trust proxy: https://expressjs.com/en/guide/behind-proxies.html
