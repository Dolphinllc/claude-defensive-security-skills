---
name: django-security-scan
description: Defensive security scan for Django and Django REST Framework projects. Detects DEBUG=True in production, wildcard ALLOWED_HOSTS, SECRET_KEY in source, missing CSRF, raw ORM queries with string formatting, mark_safe on user input, AllowAny on mutating DRF views, and ModelSerializer fields="__all__" leaking sensitive fields. Invoke when the user asks to "review", "audit", or "scan" a Django project.
---

# Django Security Scan

Defensive scan for Django (4.2+/5.x) and Django REST Framework projects. Reports findings using the [shared scoring schema](../../../SCORING.md).

## Scope

- `settings.py` / `settings/*.py`
- `views.py`, class-based views, DRF `ViewSet`s and `Serializer`s
- `urls.py`, `middleware.py`, custom managers and querysets
- Templates with `{% autoescape off %}` / `|safe`

## Procedure

1. Read settings and assess configuration first.
2. Walk views and serializers for permissions and validation.
3. Grep for `raw(`, `extra(`, `mark_safe`, `format_html`, `|safe`.

## Rules

| ID | Severity | Detection | Fix |
|----|----------|-----------|-----|
| DJ-CFG-001 | critical | `DEBUG = True` not gated by env in any settings module loaded in prod | `DEBUG = os.environ.get("DJANGO_DEBUG") == "1"` |
| DJ-CFG-002 | critical | `ALLOWED_HOSTS = ["*"]` | Pin to canonical hostnames |
| DJ-CFG-003 | critical | `SECRET_KEY = "..."` literal in repo | Read from env / secret manager; rotate immediately |
| DJ-CFG-004 | high | `SECURE_SSL_REDIRECT`, `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE` not all `True` in prod | Set all three |
| DJ-CFG-005 | high | `SECURE_HSTS_SECONDS = 0` (or unset) on a TLS site | Set ≥ 31536000 with subdomains/preload as appropriate |
| DJ-CFG-006 | medium | `X_FRAME_OPTIONS` removed or default `SAMEORIGIN` overridden to `ALLOWALL` | Keep `DENY` unless embedding is needed |
| DJ-MW-001 | high | `MIDDLEWARE` missing `CsrfViewMiddleware` or `XFrameOptionsMiddleware` | Restore default middleware order |
| DJ-CSRF-001 | high | `@csrf_exempt` on state-changing view that uses session auth | Remove decorator; if API, switch to token/header auth |
| DJ-ORM-001 | critical | `Model.objects.raw(f"...{var}...")` / `cursor.execute(f"...")` | Use parameterized: `raw("SELECT ... WHERE id=%s", [var])` |
| DJ-ORM-002 | high | `.extra(where=[f"col = '{var}'"])` | Use `.filter()` ORM constructs or parameterize |
| DJ-TPL-001 | high | `mark_safe(user_input)` / `format_html("{}", user_input)` where `{}` is unescaped intentionally | Render via template auto-escaping; never `mark_safe` user input |
| DJ-TPL-002 | medium | Template uses `{% autoescape off %}` block containing variables | Re-enable autoescape; use `|escape` selectively |
| DJ-DRF-001 | critical | DRF view `permission_classes = [AllowAny]` (or default) on mutating endpoint | Use `IsAuthenticated` (+ object-level perms) |
| DJ-DRF-002 | high | `ModelSerializer` with `fields = "__all__"` on `User`/auth/PII models | Enumerate fields; exclude `password`, `is_staff`, etc. |
| DJ-DRF-003 | medium | `SearchFilter` / `OrderingFilter` exposing fields not safe to enumerate (e.g., `password_hash`) | Define explicit `search_fields` / `ordering_fields` |
| DJ-AUTH-001 | high | `LOGIN_URL` view has no rate limiting / lockout (no `django-axes` / `django-ratelimit`) | Add `django-axes` |
| DJ-FILE-001 | high | `FileField` / `ImageField` without `validators` and used without MIME/size check on upload | Validate extension + content-type + size; store outside web root |
| DJ-CORS-001 | high | `CORS_ALLOW_ALL_ORIGINS = True` together with `CORS_ALLOW_CREDENTIALS = True` | Use `CORS_ALLOWED_ORIGINS = [...]` |

## Wrong vs. right

### DJ-DRF-002 (serializer leaks)

```python
# ❌ Exposes password hash, is_staff, etc.
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"
```

```python
# ✅ Explicit allowlist
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "date_joined"]
        read_only_fields = ["id", "date_joined"]
```

### DJ-ORM-001 (raw SQL)

```python
# ❌
User.objects.raw(f"SELECT * FROM auth_user WHERE email = '{email}'")
```

```python
# ✅
User.objects.raw("SELECT * FROM auth_user WHERE email = %s", [email])
```

### DJ-TPL-001 (mark_safe)

```python
# ❌ Stored XSS pipeline
context["bio"] = mark_safe(user.bio)
```

```python
# ✅ Let the template engine escape
context["bio"] = user.bio  # rendered as {{ bio }} — auto-escaped
```

## References

- Django security: https://docs.djangoproject.com/en/stable/topics/security/
- Deployment checklist: https://docs.djangoproject.com/en/stable/howto/deployment/checklist/
- DRF permissions: https://www.django-rest-framework.org/api-guide/permissions/
