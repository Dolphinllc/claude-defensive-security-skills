---
name: django-attack-probe
description: Authorized self-pentest probe targeting Django and DRF-specific weaknesses. Tests DEBUG-page leak, ALLOWED_HOSTS bypass via Host header, default admin path enumeration, ORM raw() injection, mass-assignment via ModelSerializer, and DRF AllowAny on mutating endpoints. Use when the user asks to "pentest" their own Django app.
---

# Django Attack Probe

Authorized probe of a Django (4.2+/5.x) app the user owns. Follow [shared probing conventions](../../../PROBING.md) — discover base URL via env / `manage.py runserver` default `8000` / `Dockerfile EXPOSE` / `docker-compose.yml`. Never hardcode the port.

## Django-specific attack surface

- **`DEBUG=True`** in dev exposes a yellow error page with full traceback, environment variables, and SQL queries — often left on in non-prod-like environments.
- **`ALLOWED_HOSTS = ['*']`** combined with `Host:` header trickery enables cache poisoning / password-reset link injection.
- **`/admin/`** is the canonical admin path; brute-force lockout depends on `django-axes`/`django-ratelimit` being installed.
- **DRF `permission_classes`** default to project-wide setting — easy to leave `AllowAny` on a single ViewSet by accident.
- **`ModelSerializer` with `fields = "__all__"`** + `update()` enables mass-assignment of `is_staff`/`is_superuser`.
- **`Model.objects.raw()` / `extra(where=...)`** with f-strings is the typical SQLi vector in Django code.

## Procedure

1. Authorization preflight + base URL discovery.
2. Liveness check: `GET /`, `GET /admin/`, `GET /api/`.
3. Run rules below.

## Rules

| ID | Severity | Probe | Confirmed when |
|----|----------|-------|----------------|
| DJ-DBG-001 | high | `GET /__nonexistent__` and any non-routed path | Response is the yellow Django debug page (`Page not found (404)` with traceback / settings dump) = `DEBUG=True` |
| DJ-HOST-001 | medium | `GET /` with `Host: evil.test` | 200 response (instead of 400 `DisallowedHost`) = `ALLOWED_HOSTS=['*']` |
| DJ-HOST-002 | medium | Trigger password-reset for a known test user with `Host: evil.test` | Reset email contains `https://evil.test/...` link = host-header injection in email links |
| DJ-ADMIN-001 | medium | `GET /admin/` then `GET /admin/login/` | 200 with Django admin login page = canonical path |
| DJ-ADMIN-002 | medium | Submit `admin/admin`, `admin/password`, `<app>/<app>` once each at `/admin/login/` (max 3 attempts) | 30x to `/admin/` = default credentials present |
| DJ-DRF-001 | critical | For each `/api/*` mutating route, send unauthenticated `POST`/`PATCH`/`DELETE` with valid JSON | 2xx response = `AllowAny` on mutation |
| DJ-DRF-002 | high | `PATCH /api/users/me/` (or similar) with `{"is_staff": true, "is_superuser": true}` | Response shows fields updated = serializer with `fields = "__all__"` |
| DJ-DRF-003 | high | `GET /api/users/?ordering=password` and `?search=password_hash` | 2xx returning data ordered by hash field = `ordering_fields = '__all__'` |
| DJ-CSRF-001 | high | Login, then cross-origin POST to a state-changing view served from `/` (not `/api/`) without CSRF cookie | 2xx = `@csrf_exempt` on a session-auth view |
| DJ-SQLI-001 | high | If a `/search?q=` exists, send `q=' UNION SELECT NULL--` and `q='||(SELECT '`. Compare timing/response | Different shape / DB error in response = `raw()`/`extra()` with concat |
| DJ-FILE-001 | high | If a download view exists, request `?file=../../etc/passwd` / `?file=../manage.py` | File contents returned = unsafe file response |
| DJ-LOGIN-001 | medium | 10 rapid `POST /accounts/login/` with random passwords | No 429 / no lockout = no rate limiting (`django-axes` not installed) |
| DJ-DEBUG-002 | low | `GET /static/` and `GET /media/` directory listings | Index returned = misconfigured static handler |

## Wrong vs. right

### DJ-DRF-002 (mass-assignment)

```python
# ❌
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"
```

```python
# ✅
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "date_joined"]
        read_only_fields = ["id", "date_joined"]
```

### DJ-HOST-002 (host-header injection in reset link)

```python
# ❌ Default reset view uses request.get_host()
# If ALLOWED_HOSTS=['*'], attacker controls the host and the link domain.
```

```python
# ✅
# settings.py
ALLOWED_HOSTS = ["app.example.com"]
DEFAULT_FROM_EMAIL = "noreply@example.com"
# Override password reset email to use a fixed BASE_URL from env, not request.get_host().
```

## References

- Django security: https://docs.djangoproject.com/en/stable/topics/security/
- Django deployment checklist: https://docs.djangoproject.com/en/stable/howto/deployment/checklist/
- DRF permissions: https://www.django-rest-framework.org/api-guide/permissions/
- django-axes: https://django-axes.readthedocs.io/
