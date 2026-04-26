---
name: express-security-scan
description: Defensive security scan for Express.js applications. Detects missing helmet, unsafe body-parser limits, broken trust-proxy config, weak cookie/session options, missing CSRF, middleware-ordering bugs (auth registered after route), unvalidated res.sendFile, and unsafe eval of request data. Invoke when the user asks to "review", "audit", or "scan" an Express project.
---

# Express Security Scan

Defensive scan for Express.js (4.x / 5.x) applications. Reports findings using the [shared scoring schema](../../../SCORING.md).

## Scope

- Files importing `express`, `express.Router`, or registering middleware on an `app`
- Session / cookie / CSRF middleware setup
- Route handlers under `routes/`, `controllers/`, `api/`

## Procedure

1. Find the `app = express()` initializer and follow `app.use(...)` calls in order — middleware order matters.
2. For each route handler, trace `req.body`/`req.params`/`req.query` into sinks.
3. Apply the rules below.

## Rules

| ID | Severity | Detection | Fix |
|----|----------|-----------|-----|
| EXP-HDR-001 | medium | `helmet()` not registered before routes | `app.use(helmet())` early in middleware chain |
| EXP-BODY-001 | high | `express.json()` / `express.urlencoded()` without `limit:` (default 100kb is fine, explicit is safer; missing limit on `body-parser` is the actual hit) | Set `limit: '1mb'` (or smaller) explicitly |
| EXP-PROXY-001 | high | `app.set('trust proxy', true)` (boolean true) when running behind a single known proxy | Use a numeric hop count or specific subnet — `true` lets clients spoof `X-Forwarded-For` |
| EXP-COOKIE-001 | high | Cookie/session set without `httpOnly: true` and `secure: true` | Add both; add `sameSite: 'lax'` or `'strict'` |
| EXP-SESS-001 | high | `express-session` with `secret` literal in code, or `secret: 'keyboard cat'` example secret | Read from env; rotate on deploy |
| EXP-SESS-002 | medium | `express-session` default `MemoryStore` in production code path | Use Redis/SQL store for prod |
| EXP-CSRF-001 | high | State-changing routes (`POST`/`PUT`/`PATCH`/`DELETE`) accept session cookies but no CSRF token check | Use `csurf` (or framework equivalent) on cookie-auth endpoints; or require custom header + `SameSite=strict` |
| EXP-ORDER-001 | critical | Auth middleware registered *after* a sensitive route on the same router | Register auth (`app.use(auth)`) before routes |
| EXP-CORS-001 | high | `cors({ origin: true, credentials: true })` (reflects any Origin) | Pin `origin` to allowlist function |
| EXP-FILE-001 | high | `res.sendFile(path.join(BASE, req.params.x))` without a containment check | Resolve and verify with `path.resolve(BASE, x).startsWith(BASE + path.sep)` |
| EXP-EVAL-001 | critical | `eval(req...)` / `new Function(req...)` / `vm.runInNewContext(req...)` | Never; redesign |
| EXP-JWT-001 | high | `jsonwebtoken.verify(token, secret)` without `algorithms:` option | Pass `algorithms: ['HS256']` (or your alg); rejects `none`/alg confusion |
| EXP-ERR-001 | medium | Default error handler missing → stack traces leak in production | Add `(err, req, res, next) => { logger.error(err); res.status(500).send('error'); }` |
| EXP-RATE-001 | medium | No `express-rate-limit` on `/login`, `/register`, `/forgot` | Apply per-IP limiter |

## Wrong vs. right

### EXP-ORDER-001 (auth registered after route)

```js
// ❌ /admin is reachable without auth
app.get('/admin', (req, res) => res.json(stats));
app.use(requireAuth);
```

```js
// ✅ Auth first
app.use(requireAuth);
app.get('/admin', (req, res) => res.json(stats));
```

### EXP-FILE-001 (path traversal)

```js
// ❌ ../../etc/passwd
app.get('/files/:name', (req, res) => {
  res.sendFile(path.join('/var/uploads', req.params.name));
});
```

```js
// ✅ Containment check
const BASE = path.resolve('/var/uploads');
app.get('/files/:name', (req, res) => {
  const target = path.resolve(BASE, req.params.name);
  if (!target.startsWith(BASE + path.sep)) return res.sendStatus(404);
  res.sendFile(target);
});
```

### EXP-JWT-001 (algorithm not pinned)

```js
// ❌ Attacker can submit alg=none or HS256-signed token where RS256 expected
jwt.verify(token, secret);
```

```js
// ✅ Pinned
jwt.verify(token, publicKey, { algorithms: ['RS256'], audience, issuer });
```

## References

- Express security best practices: https://expressjs.com/en/advanced/best-practice-security.html
- helmet: https://helmetjs.github.io/
- OWASP Cheat Sheet — Node.js: https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html
