---
name: spring-boot-attack-probe
description: Authorized self-pentest probe targeting Spring Boot-specific weaknesses. Tests Actuator endpoint exposure (/env, /heapdump, /loggers), Whitelabel error page info disclosure, h2-console exposure, Spring Security permitAll gaps, and SpEL/parameter-binding pitfalls. Use when the user asks to "pentest" their own Spring Boot app.
---

# Spring Boot Attack Probe

Authorized probe of a Spring Boot 3.x app the user owns. Follow [shared probing conventions](../../../PROBING.md) — discover base URL from `application.{properties,yml}` `server.port` (default `8080`), `Dockerfile EXPOSE`, or `docker-compose.yml`. Never hardcode.

## Spring-specific attack surface

- **Actuator endpoints** under `/actuator/*` are gold mines: `/env` (env vars including secrets), `/heapdump` (full heap → JWT secrets), `/loggers` (POST to change log level → log injection), `/configprops`, `/threaddump`. Easy to expose via `management.endpoints.web.exposure.include=*`.
- **`/h2-console`** is enabled in dev profile — any process with HTTP access can run SQL via JDBC URL pointing back to the app's DB.
- **Whitelabel error page** discloses package/class names and Spring version.
- **Mass-assignment via `@ModelAttribute`**: extra form fields auto-bind to entity fields including `id`, `roles` unless `setAllowedFields` is restricted.
- **`@RequestParam` type coercion** + missing `@PreAuthorize` = "everyone is the admin user" via `?userId=1`.

## Procedure

1. Authorization preflight + base URL discovery.
2. Liveness: `GET /`, `GET /actuator`.
3. Run rules. Several Actuator endpoints are read-only; some (`/loggers`, `/env`) accept POSTs — never write to non-test environments.

## Rules

| ID | Severity | Probe | Confirmed when |
|----|----------|-------|----------------|
| SB-ACT-001 | critical | `GET /actuator` (or `/manage`, `/admin/actuator` per `management.endpoints.web.base-path`) | 200 with HAL `_links` listing actuator endpoints |
| SB-ACT-002 | critical | `GET /actuator/env` | 200 with property sources including `spring.datasource.password`, AWS keys (values may be `******` if `sanitize` enabled — still flag as high if endpoint reachable) |
| SB-ACT-003 | critical | `GET /actuator/heapdump` (≤2MB request budget — abort if response size > 50MB) | 200 `application/octet-stream` of HPROF format |
| SB-ACT-004 | high | `GET /actuator/configprops`, `/mappings`, `/beans`, `/threaddump`, `/loggers` | Each returning 200 |
| SB-ACT-005 | high | `GET /actuator/info` | Body discloses git commit / build host / version (configured via `info.*`) |
| SB-H2-001 | critical | `GET /h2-console` | 200 H2 login form = h2-console exposed (likely dev profile in non-dev env) |
| SB-ERR-001 | medium | `GET /__nonexistent` | Default Whitelabel page exposing Spring version / stack trace |
| SB-ERR-002 | low | `GET /actuator/health` (always exposed by default) with `Accept: application/json` | Response shows `status: UP` + component details (DB host, mail) = `management.endpoint.health.show-details=always` |
| SB-AUTH-001 | critical | For each `/admin/**`, `/api/**` mutating route, send unauthenticated request | 2xx = `permitAll` chain or missing `@PreAuthorize` |
| SB-AUTH-002 | high | If JWT-based: send `Authorization: Bearer <alg=none>` then `<HS256 with public key as secret>` | 2xx = jwt verification misconfigured (very common in Spring Security tutorials) |
| SB-MA-001 | high | `POST /api/users` with extra fields `{"id": 1, "roles": ["ADMIN"], "enabled": true}` | Response shows extra fields persisted = open `@ModelAttribute` binder, missing `setAllowedFields` |
| SB-CORS-001 | high | `OPTIONS /api/*` with `Origin: https://evil.test` and `Access-Control-Request-Method: POST` | `ACAO: https://evil.test` + `ACAC: true` = `@CrossOrigin(origins = "*")` with credentials |
| SB-SPEL-001 | medium | If a search/filter accepts a SpEL-shaped string (`#root.user.password`), submit `T(java.lang.Runtime).getRuntime()` — but only `T(java.lang.System).getProperty("user.name")` (benign read) | Response contains the OS user name = SpEL evaluation reachable |
| SB-CSRF-001 | high | If `/login` is form-based and CSRF disabled in chain: cross-origin POST without `_csrf` token | 2xx = CSRF disabled on stateful endpoint |
| SB-CVE-001 | medium | Detect framework version via `/actuator/info`, server header, or static file paths; cross-reference against last 12 months of Spring Security / Spring Framework CVEs | Version matches a known affected range |

## Important: heap-dump handling

If `SB-ACT-003` returns a heap dump:
1. Do **not** download more than the first 1MB.
2. Do **not** parse it yourself for credentials.
3. Surface the finding immediately and ask the user whether to retain or discard the partial download.

## Wrong vs. right

### SB-ACT-001 (Actuator wide open)

```yaml
# ❌ application.yml
management:
  endpoints:
    web:
      exposure:
        include: "*"
```

```yaml
# ✅
management:
  endpoints:
    web:
      exposure:
        include: health, info        # only what you actually need
  endpoint:
    health:
      show-details: when-authorized
```

```java
// ✅ separate filter chain for actuator
@Bean
@Order(1)
SecurityFilterChain actuator(HttpSecurity http) throws Exception {
  http.securityMatcher("/actuator/**")
      .authorizeHttpRequests(a -> a.anyRequest().hasRole("ACTUATOR"))
      .httpBasic(withDefaults());
  return http.build();
}
```

### SB-MA-001 (mass-assignment)

```java
// ❌
@PostMapping("/users")
public User create(@ModelAttribute User user) { return repo.save(user); }
```

```java
// ✅ DTO + explicit mapping
public record CreateUserDto(@NotBlank String email, @NotBlank String name) {}

@PostMapping("/users")
public User create(@Valid @RequestBody CreateUserDto dto) {
  var u = new User(); u.setEmail(dto.email()); u.setName(dto.name());
  return repo.save(u);
}
```

## References

- Spring Boot Actuator: https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html
- Actuator security: https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html#actuator.endpoints.security
- Spring Security: https://docs.spring.io/spring-security/reference/index.html
- CVE database (filter spring-projects): https://www.cve.org/
