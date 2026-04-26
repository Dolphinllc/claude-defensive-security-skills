---
name: openapi-spec-security-scan
description: Defensive security scan for OpenAPI 3.x specifications (openapi.yaml / openapi.json). Detects missing global security, unprotected mutating operations, HTTP-only servers, loose schemas (additionalProperties true, missing required), wildcard CORS, missing 401/403 responses, PII in examples, and weakly-typed parameters. Invoke when the user asks to "review", "audit", or "scan" an OpenAPI / Swagger spec, or when editing files named openapi.{yaml,json}, swagger.{yaml,json}, or under api/ directories.
---

# OpenAPI Spec Security Scan

Defensive scan for OpenAPI 3.0 / 3.1 specifications. The spec **is** the contract — gaps here become real vulnerabilities downstream in generated servers and clients. Reports findings using the [shared scoring schema](../../SCORING.md).

## Scope

- `openapi.{yaml,yml,json}`, `swagger.{yaml,yml,json}` (any Swagger 2.0 → upgrade)
- Files referenced via `$ref` (`components/**`, `paths/**`)
- Generated server stubs only as cross-reference; rules apply to the spec itself

## Procedure

1. Parse the document (use `yaml`/`json` tooling; do not regex).
2. Resolve `$ref`s to evaluate effective schemas.
3. Walk `paths` × `methods` and apply rules below.
4. Walk `components.schemas` for type tightness.

## Rules

| ID | Severity | Detection | Fix |
|----|----------|-----------|-----|
| OAS-VER-001 | medium | Document is Swagger 2.0 (`swagger: "2.0"`) | Upgrade to OpenAPI 3.1 |
| OAS-SEC-001 | critical | No top-level `security:` and at least one mutating operation has no `security` override | Define global `security:` and override per public operation |
| OAS-SEC-002 | high | Operation `POST`/`PUT`/`PATCH`/`DELETE` has `security: []` (explicitly anonymous) | Remove or gate behind explicit auth |
| OAS-SEC-003 | high | `securitySchemes` declares `type: http, scheme: basic` and is referenced from operations served over HTTP (not HTTPS) | Require HTTPS-only (see OAS-SRV-001); prefer bearer/oauth2 |
| OAS-SEC-004 | medium | API-key scheme using `in: query` | Move to `in: header`; query strings leak via referrer/log |
| OAS-SEC-005 | medium | OAuth2 flow declares scopes that are never required by any operation (or vice-versa) | Reconcile scopes ↔ operations |
| OAS-SRV-001 | high | `servers:` contains an `http://` URL (not `https://`) for a non-localhost host | Use `https://` |
| OAS-CORS-001 | high | Spec advertises `Access-Control-Allow-Origin: *` (in response headers) on operations requiring auth | Remove wildcard; document origin allowlist |
| OAS-RESP-001 | high | Mutating operation declares `200`/`201` but no `401` and no `403` | Add `401` and `403` response refs |
| OAS-RESP-002 | medium | Operation declares `default` response only (no specific codes) | Enumerate `200`/`400`/`401`/`403`/`404`/`5xx` |
| OAS-RESP-003 | low | `5xx` response includes detailed schema (stack trace fields, internal ids) | Use generic error envelope |
| OAS-PARAM-001 | high | Path/query parameter has `type: string` without `pattern`, `enum`, `format`, or `maxLength` | Constrain — every untyped string is an injection seam |
| OAS-PARAM-002 | medium | Integer parameter without `minimum`/`maximum` (allows pagination DoS / overflow) | Set bounds |
| OAS-SCHEMA-001 | high | Object schema has `additionalProperties: true` (or default) on **request** body | Set `additionalProperties: false`; clients should not send unknown fields |
| OAS-SCHEMA-002 | medium | Object schema missing `required:` for fields that are not nullable in the implementation | Declare `required:` |
| OAS-SCHEMA-003 | medium | String field missing `maxLength` on user-supplied bodies | Add `maxLength` to bound payloads |
| OAS-SCHEMA-004 | high | Response schema for `User`/`Account`/auth model includes fields like `password`, `password_hash`, `totp_secret`, `api_key` | Remove from response schema |
| OAS-EX-001 | high | `example` / `examples` contain real-looking PII, JWTs, or API keys (entropy heuristic + key-shaped names) | Replace with synthetic placeholders |
| OAS-FILE-001 | medium | Multipart upload operation does not constrain `format: binary` size (no `maxLength` on encoding, no documented limit) | Document limits; enforce server-side |
| OAS-DEP-001 | low | Operation marked `deprecated: true` still listed without sunset date in description | Add removal timeline |
| OAS-WEBHOOK-001 | high | OpenAPI 3.1 `webhooks:` defined without a signature scheme (HMAC, JWS) documented | Document signing scheme; require it on receiver |

## Wrong vs. right

### OAS-SEC-001 (no global security)

```yaml
# ❌ paths declare no security; global is empty → all anonymous
openapi: 3.1.0
paths:
  /users:
    post:
      summary: Create user
      responses:
        "201": { $ref: "#/components/responses/User" }
```

```yaml
# ✅ Global default + explicit overrides
openapi: 3.1.0
security:
  - bearerAuth: []
paths:
  /users:
    post:
      summary: Create user
      security:
        - bearerAuth: [users.write]
      responses:
        "201": { $ref: "#/components/responses/User" }
        "401": { $ref: "#/components/responses/Unauthorized" }
        "403": { $ref: "#/components/responses/Forbidden" }
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
```

### OAS-SCHEMA-001 + OAS-PARAM-001 (loose types)

```yaml
# ❌
components:
  schemas:
    CreateUser:
      type: object
      properties:
        email: { type: string }
        role:  { type: string }
      # additionalProperties default = true
```

```yaml
# ✅
components:
  schemas:
    CreateUser:
      type: object
      additionalProperties: false
      required: [email, role]
      properties:
        email:
          type: string
          format: email
          maxLength: 254
        role:
          type: string
          enum: [member, admin]
```

### OAS-SCHEMA-004 (response leaks)

```yaml
# ❌ Returning the password hash to clients
User:
  type: object
  properties:
    id: { type: string, format: uuid }
    email: { type: string }
    password_hash: { type: string }   # ← never expose
```

```yaml
# ✅ Define a separate response model
UserPublic:
  type: object
  required: [id, email]
  additionalProperties: false
  properties:
    id: { type: string, format: uuid }
    email: { type: string, format: email }
```

### OAS-EX-001 (PII in examples)

```yaml
# ❌ Real-looking PII shipped in the spec → leaked via SDK docs / API portals
example:
  email: tanaka.taro@example.com
  phone: "+81-90-1234-5678"
  api_key: sk-live-7c8a9d1e2f3b...
```

```yaml
# ✅ Obviously synthetic
example:
  email: user@example.test
  phone: "+81-90-0000-0000"
  api_key: REPLACE_ME
```

## References

- OpenAPI 3.1: https://spec.openapis.org/oas/v3.1.0
- OWASP API Security Top 10: https://owasp.org/API-Security/
- API Stylebook — Security: https://apistylebook.com/design/topics/security
