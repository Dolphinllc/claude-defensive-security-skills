---
name: nestjs-security-scan
description: Defensive security scan for NestJS applications. Detects missing global ValidationPipe with whitelist, controllers without @UseGuards, DTOs without class-validator decorators, permissive CORS, missing helmet, exception filters leaking stack traces, TypeORM raw queries with template literals, and WebSocket gateways without auth. Invoke when the user asks to "review", "audit", or "scan" a NestJS project.
---

# NestJS Security Scan

Defensive scan for NestJS 10.x / 11.x. Reports findings using the [shared scoring schema](../../../SCORING.md).

## Scope

- `main.ts` / `bootstrap()`
- `*.controller.ts`, `*.gateway.ts`, `*.resolver.ts`
- DTO files (`*.dto.ts`)
- Modules registering `APP_GUARD`, `APP_PIPE`, `APP_FILTER`, `APP_INTERCEPTOR`

## Procedure

1. Read `main.ts` to confirm global pipes/guards/filters/helmet/CORS.
2. Walk every controller method for guards and DTOs.
3. Inspect DTO classes for class-validator decorators.

## Rules

| ID | Severity | Detection | Fix |
|----|----------|-----------|-----|
| NEST-PIPE-001 | high | No global `ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true })` in `main.ts` | Register globally; this is the single biggest input-validation lever in Nest |
| NEST-DTO-001 | high | DTO class without any `class-validator` decorators (`@IsString`, `@IsEmail`, etc.) used as `@Body()` type | Decorate every field; `@ValidateNested` for nested objects |
| NEST-DTO-002 | medium | DTO uses `any` / `Record<string, unknown>` for body | Define a typed DTO |
| NEST-GUARD-001 | critical | Mutating controller method (`@Post/@Put/@Patch/@Delete`) without `@UseGuards(...)` and no global `APP_GUARD` providing auth | Apply `@UseGuards(JwtAuthGuard)` (or global guard) |
| NEST-GUARD-002 | high | `@Public()` decorator (or `@SkipAuth()`) used on admin / write endpoints | Remove; restrict to login/health |
| NEST-CORS-001 | high | `app.enableCors({ origin: '*', credentials: true })` or `origin: true` with credentials | Provide origin allowlist function |
| NEST-HDR-001 | medium | `helmet()` not applied (`app.use(helmet())`) | Apply in `main.ts` before listen |
| NEST-EXC-001 | medium | Custom `ExceptionFilter` returning `exception.stack` / full message to client | Return generic message; log details server-side |
| NEST-TYPEORM-001 | critical | `repository.query(\`SELECT … ${var}\`)` / `manager.query` with template literal | Use `query("SELECT … WHERE id = $1", [var])` |
| NEST-TYPEORM-002 | high | `createQueryBuilder().where(\`col = '${var}'\`)` | Use `.where("col = :v", { v: var })` |
| NEST-WS-001 | high | `@WebSocketGateway()` with no `canActivate` guard on `handleConnection` and emits user-tied data | Implement auth in gateway lifecycle |
| NEST-COOKIE-001 | high | `CookieParser`/session secret literal in code | Read from `ConfigService`; require non-empty at boot |
| NEST-SWAGGER-001 | medium | `SwaggerModule.setup` mounted in production without auth on the docs path | Gate docs path behind auth or env flag |
| NEST-RATE-001 | medium | `@nestjs/throttler` not registered, or no throttle on `/auth/login` | Register `ThrottlerModule` and apply guard |

## Wrong vs. right

### NEST-PIPE-001 + NEST-DTO-001 (validation gap)

```ts
// ❌ Body is whatever the client sends
@Post()
create(@Body() body: any) { return this.svc.create(body); }
```

```ts
// ✅ main.ts
app.useGlobalPipes(new ValidationPipe({
  whitelist: true,
  forbidNonWhitelisted: true,
  transform: true,
}));

// ✅ DTO
export class CreateUserDto {
  @IsEmail() email!: string;
  @IsString() @Length(8, 128) password!: string;
  @IsOptional() @IsEnum(Role) role?: Role;
}

@Post()
create(@Body() dto: CreateUserDto) { return this.svc.create(dto); }
```

### NEST-GUARD-001 (no guard on mutation)

```ts
// ❌
@Delete(':id')
remove(@Param('id') id: string) { return this.svc.remove(id); }
```

```ts
// ✅
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('admin')
@Delete(':id')
remove(@Param('id') id: string) { return this.svc.remove(id); }
```

### NEST-TYPEORM-001 (raw query injection)

```ts
// ❌
const rows = await repo.query(`SELECT * FROM users WHERE email = '${email}'`);
```

```ts
// ✅
const rows = await repo.query('SELECT * FROM users WHERE email = $1', [email]);
```

## References

- NestJS Security: https://docs.nestjs.com/security/authentication
- ValidationPipe: https://docs.nestjs.com/techniques/validation
- class-validator: https://github.com/typestack/class-validator
