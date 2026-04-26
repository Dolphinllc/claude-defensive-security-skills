<div align="center">

# Claude Security Skills

**English** · [日本語](./README.ja.md) · [简体中文](./README.zh-CN.md)

Production-grade **defensive** and **offensive** security skills for [Claude Code](https://docs.claude.com/en/docs/claude-code) and the [Claude Agent SDK](https://docs.claude.com/en/api/agent-sdk).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](./CONTRIBUTING.md)
[![Skills](https://img.shields.io/badge/skills-25-blue)](./skills)

</div>

---

## What this is

A curated set of [Claude Skills](https://docs.claude.com/en/docs/agents-and-tools/agent-skills/overview) — opinionated, version-controlled playbooks Claude loads on demand — for hardening **modern web applications** and **generative-AI systems**.

Two complementary halves:

- **Defensive (`scan`)** — given a codebase, Claude detects misconfigurations and emits a structured findings report with severity and a 0-100 score. Idiomatic to each framework.
- **Offensive (`probe`)** — given a *running* app you own, Claude runs a rate-limited, authorization-gated battery of tests and reports what was actually exploitable. Target port is always discovered from your env / entrypoint, never hardcoded.

Out of scope: red-team tooling for third-party systems, exploit development, evasion of detection, mass scanning.

## Skill catalog

### Defensive — code review & scoring (`skills/defensive/`)

| Framework / SDK | Skill | Detects |
|---|---|---|
| Next.js | [`nextjs-security-scan`](./skills/defensive/web/nextjs-security-scan) | env leaks, server actions, middleware, CORS, CSP |
| Express | [`express-security-scan`](./skills/defensive/web/express-security-scan) | middleware order, helmet, jwt, sendFile traversal |
| Django / DRF | [`django-security-scan`](./skills/defensive/web/django-security-scan) | DEBUG, raw ORM, mark_safe, AllowAny, fields="__all__" |
| Spring Boot | [`spring-boot-security-scan`](./skills/defensive/web/spring-boot-security-scan) | permitAll, CSRF, JdbcTemplate, Jackson, actuator |
| FastAPI | [`fastapi-security-scan`](./skills/defensive/web/fastapi-security-scan) | Depends, JWT, Pydantic, SQL, path traversal |
| NestJS | [`nestjs-security-scan`](./skills/defensive/web/nestjs-security-scan) | ValidationPipe, guards, DTOs, TypeORM raw |
| OpenAPI | [`openapi-spec-security-scan`](./skills/defensive/web/openapi-spec-security-scan) | global security, schema tightness, response leaks |
| Anthropic SDK | [`anthropic-sdk-security-scan`](./skills/defensive/genai/anthropic-sdk-security-scan) | prompt injection, tool input, prompt-cache PII |
| OpenAI SDK | [`openai-sdk-security-scan`](./skills/defensive/genai/openai-sdk-security-scan) | function args, structured output, Assistants threads |
| Vercel AI SDK | [`vercel-ai-sdk-security-scan`](./skills/defensive/genai/vercel-ai-sdk-security-scan) | tool execute, attachments, streamText XSS |
| LangChain | [`langchain-security-scan`](./skills/defensive/genai/langchain-security-scan) | REPL/Shell, RAG trust, callbacks |
| MCP server | [`mcp-server-security-scan`](./skills/defensive/genai/mcp-server-security-scan) | tool fs/exec/SSRF, transport auth |

Findings format: [`skills/SCORING.md`](./skills/SCORING.md).

### Offensive — self-pentest of your own app (`skills/offensive/`)

| Framework / SDK | Skill | Probes |
|---|---|---|
| *(any)* | [`webapp-pentest-checklist`](./skills/offensive/web/webapp-pentest-checklist) | OWASP Web/API Top 10 baseline |
| Express | [`express-attack-probe`](./skills/offensive/web/express-attack-probe) | prototype pollution, HPP, trust-proxy spoofing |
| Django | [`django-attack-probe`](./skills/offensive/web/django-attack-probe) | DEBUG leak, host injection, DRF AllowAny, mass-assign |
| Spring Boot | [`spring-boot-attack-probe`](./skills/offensive/web/spring-boot-attack-probe) | actuator, h2-console, JWT confusion, mass-assign |
| Next.js | [`nextjs-attack-probe`](./skills/offensive/web/nextjs-attack-probe) | NEXT_PUBLIC leak, middleware bypass, server-action auth |
| FastAPI | [`fastapi-attack-probe`](./skills/offensive/web/fastapi-attack-probe) | OpenAPI enum, Depends gaps, Pydantic extra fields |
| NestJS | [`nestjs-attack-probe`](./skills/offensive/web/nestjs-attack-probe) | ValidationPipe, guard misses, ws auth |
| *(any)* | [`prompt-injection-probe`](./skills/offensive/genai/prompt-injection-probe) | direct/indirect/multi-turn injection battery |
| Anthropic SDK | [`anthropic-sdk-attack-probe`](./skills/offensive/genai/anthropic-sdk-attack-probe) | XML tag confusion, prefill abuse, tool input |
| OpenAI SDK | [`openai-sdk-attack-probe`](./skills/offensive/genai/openai-sdk-attack-probe) | function args, structured-output bypass, threads |
| Vercel AI SDK | [`vercel-ai-sdk-attack-probe`](./skills/offensive/genai/vercel-ai-sdk-attack-probe) | tool execute, useChat auth, markdown XSS |
| LangChain | [`langchain-attack-probe`](./skills/offensive/genai/langchain-attack-probe) | REPL/Shell, RAG injection, shared memory |
| MCP server | [`mcp-server-attack-probe`](./skills/offensive/genai/mcp-server-attack-probe) | path traversal, transport auth, SSRF, DNS rebinding |

Probing rules: [`skills/PROBING.md`](./skills/PROBING.md).

## Quick start

### Claude Code

Pull the skills you need into your project (recommended) or user scope:

```bash
# Project scope (committed alongside your code)
git clone https://github.com/Dolphinllc/claude-security-skills.git /tmp/css
mkdir -p .claude/skills
cp -r /tmp/css/skills/defensive/web/nextjs-security-scan .claude/skills/

# User scope (available in every project)
cp -r /tmp/css/skills/defensive/web/nextjs-security-scan ~/.claude/skills/
```

Claude Code auto-discovers the skill on next launch. Invoke with `/<skill-name>` or let Claude trigger it when its `description` matches the task.

### Claude Agent SDK

Mount the `skills/` directory as a skill source per the [Agent SDK docs](https://docs.claude.com/en/api/agent-sdk).

## Authorization for offensive skills

Every offensive skill follows [`skills/PROBING.md`](./skills/PROBING.md):

- Default targets: `localhost`, `127.0.0.1`, `*.localhost`. Anything else requires explicit confirmation.
- Target port resolved from env (`PORT`, `BASE_URL`, etc.) or your project entrypoint (`package.json`, `Dockerfile`, `application.yml`, ...). Never hardcoded.
- No DoS, no credential brute-force at scale, no third-party systems, no detection evasion.
- Request budget capped per scan; results emitted in a structured schema.

If you can't satisfy these, the skill returns a single `PREFLIGHT-BLOCKED` finding and stops.

## Contributing

PRs welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md). In short, a skill is ready to merge when it:

1. Solves a concrete defensive or offensive task — not a generic security overview.
2. Has a `description` precise enough for Claude to self-select it.
3. Includes at least one wrong-vs-right code example.
4. Cites authoritative sources (OWASP, NIST, vendor docs, CVE).

## License

[MIT](./LICENSE) © Dolphin LLC.

## Maintainer

[Dolphin LLC](https://github.com/Dolphinllc)
