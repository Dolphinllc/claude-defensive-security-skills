---
name: fastapi-attack-probe
description: Authorized self-pentest probe targeting FastAPI-specific weaknesses. Tests /docs and /redoc auth, OpenAPI schema enumeration, Pydantic boundary bypass via extra fields, missing Depends/Security on routes, JWT alg confusion, and unsafe file responses. Use when the user asks to "pentest" their own FastAPI app.
---

# FastAPI Attack Probe

Authorized probe of a FastAPI 0.100+ app the user owns. Follow [shared probing conventions](../../../PROBING.md) — discover base URL from env (`UVICORN_PORT`, `PORT`), `pyproject.toml` task definitions, `Dockerfile EXPOSE`, or default `uvicorn` `8000`. Never hardcode.

## FastAPI-specific attack surface

- **`/docs` and `/redoc`** are public by default — they expose the full route inventory and request schemas.
- **`/openapi.json`** is the most efficient enumeration target — fetch it once and you have every route, method, parameter type, and security requirement.
- **`Depends`/`Security`** is opt-in per route. A single missing `Depends(get_current_user)` on a mutating route is "anonymous admin" by default.
- **Pydantic v2 default `extra='ignore'`** silently drops unknown fields; combined with response models it can leak fields not declared in the request schema.
- **JWT verification** misconfig is endemic in FastAPI tutorials (`jwt.decode` without `algorithms=`).

## Procedure

1. Authorization preflight + base URL discovery.
2. Fetch the OpenAPI spec once: `GET /openapi.json` (also try `/api/openapi.json`, `/v1/openapi.json`). Use it to drive the rest of the scan.
3. Probe per rule table.

## Rules

| ID | Severity | Probe | Confirmed when |
|----|----------|-------|----------------|
| FA-DOC-001 | medium | `GET /docs`, `GET /redoc`, `GET /openapi.json` | 200 = docs publicly exposed (medium because it accelerates other attacks; not directly exploitable) |
| FA-AUTH-001 | critical | For each operation in `/openapi.json` that lacks a `security` requirement and is `POST/PUT/PATCH/DELETE`, send a request without auth | 2xx = `Depends(get_current_user)` missing |
| FA-AUTH-002 | high | For routes declaring `security: [HTTPBearer]`, send `Authorization: Bearer <obviously-invalid>` | 2xx = dependency returns `None` instead of raising 401 |
| FA-JWT-001 | critical | Send `Authorization: Bearer eyJhbGciOiJub25lIn0.<payload>.` (alg=none); also send token signed with public key as secret using HS256 | 2xx = `jwt.decode` without `algorithms=` |
| FA-JWT-002 | high | Send token with `iss=https://evil.test`, `aud=evil` | 2xx = no `audience`/`issuer` checks |
| FA-PYD-001 | high | Find a `PATCH`/`PUT` route with body schema; send `{...valid..., "is_admin": true, "role": "admin"}` | Updated record reflects extra field = `dict`/`Any` body OR custom assignment without `model_dump(exclude_unset=True, by_alias=...)` |
| FA-PYD-002 | medium | Same route with field types intentionally wrong (string for int) | 500 with traceback (instead of 422) = exception not handled |
| FA-CORS-001 | high | `OPTIONS /api/*` with `Origin: https://evil.test` + `Access-Control-Request-Method: POST` | `ACAO` reflected with `ACAC: true` = `allow_origins=["*"]` + credentials, or origin reflection |
| FA-FILE-001 | high | If a `FileResponse` route exists (`GET /files/{name}`), request `?name=..%2F..%2F.env`, `?name=..%2F..%2Fpyproject.toml` | Response body matches the file = path traversal |
| FA-DBG-001 | medium | Trigger an error via malformed JSON / bad type | 500 response with full Python traceback (file paths, line numbers) = `app = FastAPI(debug=True)` in this env |
| FA-RATE-001 | medium | 10 rapid `POST /login` (or schema-discovered auth route) | All 200/401 without 429 = no `slowapi`/`fastapi-limiter` |
| FA-WS-001 | medium | If `/ws` exists in OpenAPI, open WebSocket without auth headers/cookies | Accepted + receives messages = WebSocket bypass |

## Wrong vs. right

### FA-AUTH-001 (missing dependency)

```python
# ❌
@router.delete("/users/{user_id}")
async def delete_user(user_id: int):
    await users.delete(user_id)
```

```python
# ✅
@router.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
):
    if current_user.id != user_id and not current_user.is_admin:
        raise HTTPException(status_code=403)
    await users.delete(user_id)
```

### FA-JWT-001 (alg confusion)

```python
# ❌
payload = jwt.decode(token, options={"verify_signature": False})
# or
payload = jwt.decode(token, SECRET)   # no algorithms= → defaults vary by lib
```

```python
# ✅
payload = jwt.decode(
    token,
    PUBLIC_KEY,
    algorithms=["RS256"],
    audience="my-api",
    issuer="https://issuer.example.com",
)
```

### FA-PYD-001 (extra-field bypass)

```python
# ❌
class UserUpdate(BaseModel):
    name: str | None = None
    email: str | None = None

@router.patch("/users/me")
async def patch_me(body: dict, user: User = Depends(...)):  # dict, not UserUpdate
    for k, v in body.items():
        setattr(user, k, v)
    await user.save()
```

```python
# ✅
class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = None
    email: str | None = None

@router.patch("/users/me")
async def patch_me(body: UserUpdate, user: User = Depends(...)):
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(user, k, v)
    await user.save()
```

## References

- FastAPI Security: https://fastapi.tiangolo.com/tutorial/security/
- OpenAPI: https://fastapi.tiangolo.com/advanced/openapi-callbacks/
- PyJWT: https://pyjwt.readthedocs.io/en/stable/usage.html
