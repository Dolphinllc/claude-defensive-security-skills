# Offensive Probing Conventions

Shared rules for every skill under `skills/offensive/`. These skills are designed for **authorized testing of the user's own application** — not external systems.

## Authorization preflight (MANDATORY)

Before sending any request, every offensive skill must:

1. **Confirm the target belongs to the user.** Default targets are `localhost`, `127.0.0.1`, `::1`, `*.localhost`, or hosts the user has explicitly named in this session. Refuse to probe any other host without an explicit go-ahead.
2. **Refuse out-of-scope behavior.** No DoS payloads, no credential brute-force at scale (>10 attempts per probe), no WAF/IDS evasion, no persistence, no lateral movement, no third-party systems.
3. **Stop on first sign of damage.** If a probe returns a 5xx with a stack trace mentioning data corruption, transactions, or external services — pause and surface to the user instead of continuing.

If any of these can't be satisfied, return a finding of severity `info` named `PREFLIGHT-BLOCKED` and stop.

## Target discovery (NEVER hardcode the port)

Resolve the target base URL in this order — stop at the first hit:

1. **Explicit user input** in this conversation (e.g., "test against http://localhost:8123").
2. **Environment variables** in shell or `.env*`: `BASE_URL`, `APP_URL`, `TEST_URL`, `PORT`, `APP_PORT`, `HOST`.
3. **Project entrypoint files**, in this order — read but do not execute:
   - Node: `package.json` `scripts.dev` / `scripts.start`, `next.config.{js,ts,mjs}`, `vite.config.*`, `nest-cli.json`, `Procfile`
   - Python: `manage.py runserver` default (`8000`), `pyproject.toml` `[tool.uvicorn]` / `[tool.poe.tasks]`, `Dockerfile` `EXPOSE`, `docker-compose.{yml,yaml}` service ports, `gunicorn.conf.py`
   - Java: `application.{properties,yml}` `server.port`, `build.gradle` Spring Boot plugin defaults, `Dockerfile` `EXPOSE`
   - Generic: `docker-compose.{yml,yaml}` published ports, `Procfile`, `Makefile` targets
4. **Ask the user.** If still ambiguous, ask — do not guess.

Record the resolved value as `target.base_url` and `target.discovered_via` (e.g., `"docker-compose.yml service=web port=3000"`) in the report header.

## Output schema

Each scan returns one block, extending the [defensive scoring schema](./SCORING.md):

```yaml
scan: <skill-name>
target:
  base_url: http://localhost:3000
  discovered_via: <where the URL came from>
  authorized_by: <"localhost-default" | "user-confirmed">
findings:
  - id: <SKILL-CATEGORY-NNN>
    severity: critical | high | medium | low | info
    rule: <short rule description>
    request: |
      <method, path, headers, body — redact secrets>
    response: |
      <status, key headers, response excerpt — first 500 bytes, redact PII>
    interpretation: <one sentence on why this indicates the issue>
    fix: <remediation, idiomatic for the framework>
    refs:
      - <authoritative URL>
score: 0-100
summary: "<N critical, N high, ...>"
notes: <false-positive risk; assumptions made>
```

## Severity rules for offensive findings

Same weights as `SCORING.md`. Plus:

- **Confirmed exploit** (you obtained data you shouldn't have, or executed a state change you shouldn't be able to) → bump one level, never lower than `high`.
- **Plausible-but-unconfirmed** (response differs in a suggestive way but no impact demonstrated) → cap at `medium`.
- **Behavioral signal only** (e.g., header missing) — that's a *defensive* finding, not offensive. Use the matching defensive skill instead.

## Throttling

- Max 3 requests/second to `localhost`, max 1 req/sec to any user-confirmed remote host.
- Total request budget per scan: 200 requests by default. Surface to the user before exceeding.

## What NEVER to include in a probe

- Working RCE payloads beyond a benign command (`echo`, `id`) needed only to confirm code path.
- Credential dumping or password lists (use only 1-3 obvious-default credentials per service: `admin/admin`, `test/test`, `<app>/<app>`).
- Persistence, post-exploitation, log clearing, AV/EDR evasion.
- Payloads targeting third-party SaaS services or CDNs even if linked from the app.
- Anything that would fail the [Anthropic usage policy](https://www.anthropic.com/legal/aup).
