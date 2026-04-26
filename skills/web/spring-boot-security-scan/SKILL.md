---
name: spring-boot-security-scan
description: Defensive security scan for Spring Boot applications using Spring Security. Detects permitAll on sensitive routes, disabled CSRF on stateful endpoints, wildcard CORS with credentials, missing @PreAuthorize, JdbcTemplate string concatenation, Jackson default typing, exposed actuators, and weak BCrypt strength. Invoke when the user asks to "review", "audit", or "scan" a Spring Boot project.
---

# Spring Boot Security Scan

Defensive scan for Spring Boot 3.x with Spring Security 6.x. Reports findings using the [shared scoring schema](../../SCORING.md).

## Scope

- `*Application.java` and `@Configuration` classes
- `SecurityFilterChain` beans / `WebSecurityConfigurerAdapter` (legacy)
- `@RestController` / `@Controller` classes
- `application.{properties,yml}`
- Repositories / DAOs using `JdbcTemplate`, `EntityManager`, native queries

## Procedure

1. Locate every `SecurityFilterChain` bean and read the request-matcher rules in order — first match wins.
2. Walk controller methods for `@PreAuthorize` / `@Secured` / endpoint-level rules.
3. Inspect data-access layer for native queries built by string concat.
4. Inspect `application.{properties,yml}` for secrets and actuator exposure.

## Rules

| ID | Severity | Detection | Fix |
|----|----------|-----------|-----|
| SB-SEC-001 | critical | `SecurityFilterChain` with `.anyRequest().permitAll()` | `.anyRequest().authenticated()` (whitelist exceptions explicitly) |
| SB-SEC-002 | high | `.csrf(csrf -> csrf.disable())` on a stateful (cookie-session) app | Keep CSRF enabled; disable only for stateless JWT APIs and document why |
| SB-SEC-003 | high | Custom matcher allows `/actuator/**` or `/admin/**` without role check | Require `hasRole("ADMIN")` |
| SB-SEC-004 | medium | `httpBasic()` enabled together with form login on the same chain (auth confusion) | Pick one mechanism per chain |
| SB-CORS-001 | high | `@CrossOrigin(origins = "*")` with `allowCredentials = "true"` | Pin origins via `CorsConfigurationSource` allowlist |
| SB-CTRL-001 | high | `@RestController` method performing mutation lacks `@PreAuthorize` and the chain's matcher only requires `authenticated()` | Add `@PreAuthorize("hasRole('...')")` or tighten chain |
| SB-CTRL-002 | medium | `@RequestMapping` without `method =` on mutating endpoints (accepts GET) | Use `@PostMapping` / `@PutMapping` etc. |
| SB-VALID-001 | high | `@RequestBody` parameter not annotated with `@Valid` / `@Validated` | Add `@Valid`; declare constraints on DTO |
| SB-SQL-001 | critical | `jdbcTemplate.query("... " + var + " ...", ...)` or `String.format` into SQL | Use `?` placeholders + args array, or `NamedParameterJdbcTemplate` |
| SB-SQL-002 | high | `@Query(value = "SELECT ... WHERE col = '" + ... )` (concat) — or `nativeQuery=true` with String.format | Bind via `:param` |
| SB-JACKSON-001 | critical | `ObjectMapper.activateDefaultTyping(...)` / `enableDefaultTyping()` enabled on input deserialization | Remove default typing; use `@JsonTypeInfo` allowlist |
| SB-CFG-001 | critical | `application.{properties,yml}` contains literal credentials (`spring.datasource.password=...`, API keys) | Externalize via env / Vault; rotate |
| SB-ACT-001 | high | `management.endpoints.web.exposure.include=*` without securing actuator chain | Enumerate exposed endpoints; require `ACTUATOR` role |
| SB-ACT-002 | medium | `/actuator/heapdump`, `/actuator/env`, `/actuator/configprops` exposed | Disable or restrict to internal network |
| SB-PWD-001 | high | `BCryptPasswordEncoder()` default strength used (10) for high-value accounts — acceptable but consider 12 | Use `BCryptPasswordEncoder(12)` for admin tier |
| SB-PWD-002 | critical | `NoOpPasswordEncoder` / plaintext comparison | Use `BCryptPasswordEncoder` or `Argon2PasswordEncoder` |
| SB-LOG-001 | medium | `log.info("user={}", user)` where `user` toString includes hash/PII | Override `toString` to redact or log id only |

## Wrong vs. right

### SB-SEC-001 (permitAll)

```java
// ❌ Everything is open
http
  .authorizeHttpRequests(a -> a.anyRequest().permitAll())
  .build();
```

```java
// ✅ Default-deny + explicit whitelist
http
  .authorizeHttpRequests(a -> a
    .requestMatchers("/", "/health", "/login").permitAll()
    .requestMatchers("/admin/**").hasRole("ADMIN")
    .anyRequest().authenticated())
  .build();
```

### SB-SQL-001 (string concat)

```java
// ❌
jdbcTemplate.query("SELECT * FROM users WHERE email = '" + email + "'", rowMapper);
```

```java
// ✅
jdbcTemplate.query("SELECT * FROM users WHERE email = ?", rowMapper, email);
```

### SB-JACKSON-001 (default typing)

```java
// ❌ Polymorphic deserialization → RCE gadget chains
mapper.activateDefaultTyping(LaissezFaireSubTypeValidator.instance);
```

```java
// ✅ Allowlist subtypes via annotations
@JsonTypeInfo(use = Id.NAME, property = "type")
@JsonSubTypes({ @Type(Cat.class, name = "cat"), @Type(Dog.class, name = "dog") })
public abstract class Pet { }
```

## References

- Spring Security: https://docs.spring.io/spring-security/reference/index.html
- Spring Boot Actuator: https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html
- OWASP Cheat Sheet — Java: https://cheatsheetseries.owasp.org/cheatsheets/Java_Security_Cheat_Sheet.html
