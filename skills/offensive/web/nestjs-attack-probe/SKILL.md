---
name: nestjs-attack-probe
description: Authorized self-pentest probe targeting NestJS-specific weaknesses. Tests global ValidationPipe gaps, missing @UseGuards on controller methods, default Swagger/OpenAPI exposure, WebSocket Gateway auth bypass, and TypeORM/Prisma raw query injection points discovered via OpenAPI. Use when the user asks to "pentest" their own NestJS app.
---

# NestJS Attack Probe

Authorized probe of a NestJS 10.x/11.x app the user owns. Follow [shared probing conventions](../../../PROBING.md) — discover base URL from `main.ts` `app.listen(...)`, `process.env.PORT`, `Dockerfile EXPOSE`, or `nest-cli.json`. Never hardcode.

## NestJS-specific attack surface

- **Validation is opt-in:** `app.useGlobalPipes(new ValidationPipe())` without `whitelist: true` allows extra fields to flow through to handlers, defeating DTO-based validation.
- **Guards are opt-in:** `@UseGuards()` on a controller class is per-class; per-method overrides + a missed method = anonymous endpoint.
- **`@nestjs/swagger`** auto-mounts `/api` (or configured path) — by default unauthenticated.
- **WebSocket Gateways** don't use the HTTP guard chain; they need their own auth in `handleConnection`.
- **`@ApiBearerAuth()` decorator** is documentation only; it does not enforce the bearer token.

## Procedure

1. Authorization preflight + base URL discovery.
2. Fetch Swagger if exposed: try `/api`, `/api/docs`, `/swagger`, `/docs`. The OpenAPI JSON is usually at `<docs>/json` or `/api-json`.
3. Probe per rule table.

## Rules

| ID | Severity | Probe | Confirmed when |
|----|----------|-------|----------------|
| NEST-DOC-001 | medium | `GET /api`, `/swagger`, `/docs` | 200 Swagger UI = docs exposed (use as enumeration aid) |
| NEST-AUTH-001 | critical | For each mutating route in OpenAPI without a `security` requirement, send unauthenticated request | 2xx = `@UseGuards` missing |
| NEST-AUTH-002 | high | For routes with `security: bearerAuth`, send obviously-malformed token | 2xx = guard returns `true` instead of throwing |
| NEST-PIPE-001 | high | Submit a body with extra fields not in DTO (`{"role": "admin", ...valid...}`) | Response shows extra field accepted = `whitelist: true` not set; combined with mass-assignment lookup → high |
| NEST-PIPE-002 | medium | Submit body with type-confusion (string where number expected) | 500 instead of 422 = transformation/validation pipe partially configured |
| NEST-DTO-001 | medium | Find a DTO without class-validator decorators (parse OpenAPI: `properties` with no constraints); send semantically invalid data (e.g., `email: "not-email"`) | 2xx = no `@IsEmail()` enforcement |
| NEST-WS-001 | high | If `/socket.io` or custom gateway endpoint advertised, connect without auth header | Connection upgraded + message received = no `canActivate` in `handleConnection` |
| NEST-CORS-001 | high | `OPTIONS /api/*` with `Origin: https://evil.test` and credentials | `ACAO` + `ACAC: true` = `enableCors({ origin: '*' or true, credentials: true })` |
| NEST-EXC-001 | medium | Force an error via malformed JSON / DB constraint violation | 500 with full stack / class names = exception filter leaking |
| NEST-COOKIE-001 | high | Login, capture cookie. Test `httpOnly`, `secure`, `sameSite` flags via `Set-Cookie` header | Missing flags = misconfigured `cookie-parser`/session |
| NEST-RATE-001 | medium | 10 rapid `POST /auth/login` | No 429 = `@nestjs/throttler` not registered |

## Wrong vs. right

### NEST-PIPE-001 (extra-field bypass)

```ts
// ❌ main.ts — pipe registered without whitelist
app.useGlobalPipes(new ValidationPipe());
```

```ts
// ✅
app.useGlobalPipes(new ValidationPipe({
  whitelist: true,
  forbidNonWhitelisted: true,
  transform: true,
}));
```

### NEST-AUTH-001 (per-method guard miss)

```ts
// ❌ Class guard, but one method missing decoration override + decorator removed
@Controller("orders")
@UseGuards(JwtAuthGuard)
export class OrdersController {
  @Get() list() { /* guarded */ }
  @Public()                        // someone added this for tests, forgot to remove
  @Delete(":id") remove() { /* now anonymous */ }
}
```

```ts
// ✅
@Controller("orders")
@UseGuards(JwtAuthGuard, RolesGuard)
export class OrdersController {
  @Get() list() { /* ... */ }
  @Roles("admin")
  @Delete(":id") remove() { /* ... */ }
}
```

## References

- NestJS Validation: https://docs.nestjs.com/techniques/validation
- NestJS Guards: https://docs.nestjs.com/guards
- NestJS WebSockets: https://docs.nestjs.com/websockets/gateways
- @nestjs/swagger: https://docs.nestjs.com/openapi/introduction
