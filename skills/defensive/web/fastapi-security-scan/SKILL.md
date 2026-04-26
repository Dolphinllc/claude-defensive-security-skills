---
name: fastapi-security-scan
description: Defensive security scan for FastAPI applications. Detects missing Depends/Security guards, Pydantic validation bypasses, permissive CORS, unverified JWTs, raw SQL string interpolation, and unsafe file responses. Invoke when the user asks to "review", "audit", or "scan" a FastAPI project, or when editing routers and dependencies.
---

# FastAPI Security Scan

Defensive scan for FastAPI projects (FastAPI 0.100+, Pydantic v2). Reports findings using the [shared scoring schema](../../../SCORING.md).

## Scope

- `**/*.py` files containing `APIRouter`, `FastAPI`, or `Depends`
- `main.py` / app factory
- `pyproject.toml` for known-vulnerable pins

Out of scope: deployment (uvicorn/gunicorn flags), dependency CVEs.

## Procedure

1. Locate the `FastAPI()` instance and all `APIRouter` instances.
2. For each route function, walk parameters and decorators.
3. Apply rules below. Emit findings in the shared schema.

## Rules

| ID | Severity | Detection | Fix |
|----|----------|-----------|-----|
| FASTAPI-AUTH-001 | critical | Mutating route (`POST`/`PUT`/`PATCH`/`DELETE`) with no `Depends`/`Security` parameter referring to an auth function | Add `current_user: User = Depends(get_current_user)` |
| FASTAPI-AUTH-002 | high | Auth dependency exists but does not raise on missing/invalid token (returns `None` and route doesn't check) | Raise `HTTPException(401)` inside the dependency |
| FASTAPI-JWT-001 | critical | `jwt.decode(..., options={"verify_signature": False})` or `jwt.decode` without `algorithms=` | Always pass `algorithms=["RS256"]` (or your alg); never disable signature verification |
| FASTAPI-JWT-002 | high | JWT decode without `audience=` / `issuer=` checks | Pass `audience` and `issuer` explicitly |
| FASTAPI-PYD-001 | high | Route function takes `dict` or `Any` as body parameter (bypasses Pydantic validation) | Define a Pydantic `BaseModel` and use it as the parameter type |
| FASTAPI-PYD-002 | medium | Pydantic model uses `model_config = ConfigDict(extra="allow")` on input boundary | Use `extra="forbid"` for inbound payloads |
| FASTAPI-CORS-001 | high | `CORSMiddleware` with `allow_origins=["*"]` and `allow_credentials=True` | Pin origins to an allowlist when credentials are allowed |
| FASTAPI-CORS-002 | medium | `CORSMiddleware` with `allow_methods=["*"]` and `allow_headers=["*"]` on auth-sensitive routes | Enumerate explicit methods/headers |
| FASTAPI-SQL-001 | critical | f-string / `%`-formatting / `.format()` building SQL passed to `execute()` / `text()` | Use parameterized queries: `text("SELECT … WHERE id=:id"), {"id": id}` |
| FASTAPI-SQL-002 | high | SQLAlchemy `Session.execute(text(user_input))` without bind params | Use bind params or ORM constructs |
| FASTAPI-FILE-001 | high | `FileResponse(path)` where `path` is built from request input without `pathlib.Path.resolve()` containment check | Resolve under a fixed base dir and verify with `is_relative_to` |
| FASTAPI-DBG-001 | high | `app = FastAPI(debug=True)` in production code path, or `--reload` defaulted on | Default `debug=False`; gate behind env var |
| FASTAPI-EXC-001 | medium | Custom exception handler returning `repr(exc)` / `traceback.format_exc()` to clients | Log details server-side; return generic message to client |
| FASTAPI-RATE-001 | medium | No rate-limiter (`slowapi`, `fastapi-limiter`) on `/login`, `/register`, `/forgot-password` | Apply per-IP limiter |
| FASTAPI-PWD-001 | high | Password compared with `==` or hashed with `hashlib.md5/sha1/sha256` directly | Use `passlib[bcrypt]` or `argon2-cffi` |

## Wrong vs. right

### FASTAPI-AUTH-001 (missing dependency)

```python
# ❌ Anyone can delete any user
@router.delete("/users/{user_id}")
async def delete_user(user_id: int):
    await users.delete(user_id)
```

```python
# ✅ Auth dependency + ownership check
@router.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
):
    if current_user.id != user_id and not current_user.is_admin:
        raise HTTPException(status_code=403)
    await users.delete(user_id)
```

### FASTAPI-JWT-001 (signature verification disabled)

```python
# ❌ Anyone can mint tokens
payload = jwt.decode(token, options={"verify_signature": False})
```

```python
# ✅ Verified
payload = jwt.decode(
    token,
    PUBLIC_KEY,
    algorithms=["RS256"],
    audience="my-api",
    issuer="https://issuer.example.com",
)
```

### FASTAPI-SQL-001 (string-formatted SQL)

```python
# ❌ Injection
await session.execute(text(f"SELECT * FROM users WHERE email = '{email}'"))
```

```python
# ✅ Parameterized
await session.execute(
    text("SELECT * FROM users WHERE email = :email"),
    {"email": email},
)
```

### FASTAPI-FILE-001 (path traversal)

```python
# ❌ ../../etc/passwd
@router.get("/files/{name}")
async def get_file(name: str):
    return FileResponse(f"/var/uploads/{name}")
```

```python
# ✅ Containment check
BASE = Path("/var/uploads").resolve()

@router.get("/files/{name}")
async def get_file(name: str):
    target = (BASE / name).resolve()
    if not target.is_relative_to(BASE) or not target.is_file():
        raise HTTPException(404)
    return FileResponse(target)
```

## References

- FastAPI Security: https://fastapi.tiangolo.com/tutorial/security/
- FastAPI Dependencies: https://fastapi.tiangolo.com/tutorial/dependencies/
- OWASP API Security Top 10: https://owasp.org/API-Security/
- PyJWT: https://pyjwt.readthedocs.io/en/stable/usage.html
