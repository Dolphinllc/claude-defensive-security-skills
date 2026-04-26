<div align="center">

# Claude Security Skills

[English](./README.md) · [日本語](./README.ja.md) · **简体中文**

面向 [Claude Code](https://docs.claude.com/en/docs/claude-code) 与 [Claude Agent SDK](https://docs.claude.com/en/api/agent-sdk) 的生产级**防御**与**进攻**安全技能集。

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](./CONTRIBUTING.md)
[![Skills](https://img.shields.io/badge/skills-25-blue)](./skills)

</div>

---

## 项目简介

一组精心整理的 [Claude Skills](https://docs.claude.com/en/docs/agents-and-tools/agent-skills/overview)(Claude 按需加载、版本受控的可复用 playbook),用于加固**现代 Web 应用**与**生成式 AI 系统**。

由两部分互补构成:

- **防御 (`scan`)** — 给定代码库,Claude 检测配置缺陷并生成带严重等级和 0–100 综合评分的结构化报告,每条规则贴合各框架的惯用法。
- **进攻 (`probe`)** — 针对**你自己拥有**的、正在运行的应用,Claude 在限速与授权前置检查下执行一组测试,报告可被实际复现的问题。目标端口始终从 env / 入口文件中解析,绝不硬编码。

不在范围内: 针对第三方系统的红队动作、漏洞利用开发、检测规避、大规模扫描。

## 技能目录

### 防御 — 代码审查与评分 (`skills/defensive/`)

| 框架 / SDK | 技能 | 主要检测项 |
|---|---|---|
| Next.js | [`nextjs-security-scan`](./skills/defensive/web/nextjs-security-scan) | env 泄漏、server actions、middleware、CORS、CSP |
| Express | [`express-security-scan`](./skills/defensive/web/express-security-scan) | 中间件顺序、helmet、jwt、sendFile 路径穿越 |
| Django / DRF | [`django-security-scan`](./skills/defensive/web/django-security-scan) | DEBUG、raw ORM、mark_safe、AllowAny、`fields="__all__"` |
| Spring Boot | [`spring-boot-security-scan`](./skills/defensive/web/spring-boot-security-scan) | permitAll、CSRF、JdbcTemplate、Jackson、actuator |
| FastAPI | [`fastapi-security-scan`](./skills/defensive/web/fastapi-security-scan) | Depends、JWT、Pydantic、SQL、路径穿越 |
| NestJS | [`nestjs-security-scan`](./skills/defensive/web/nestjs-security-scan) | ValidationPipe、Guard、DTO、TypeORM raw |
| OpenAPI | [`openapi-spec-security-scan`](./skills/defensive/web/openapi-spec-security-scan) | 全局 security、schema 紧致度、响应字段泄漏 |
| Anthropic SDK | [`anthropic-sdk-security-scan`](./skills/defensive/genai/anthropic-sdk-security-scan) | 提示注入、tool input、prompt-cache PII |
| OpenAI SDK | [`openai-sdk-security-scan`](./skills/defensive/genai/openai-sdk-security-scan) | function args、structured output、Assistants threads |
| Vercel AI SDK | [`vercel-ai-sdk-security-scan`](./skills/defensive/genai/vercel-ai-sdk-security-scan) | tool execute、attachments、streamText XSS |
| LangChain | [`langchain-security-scan`](./skills/defensive/genai/langchain-security-scan) | REPL/Shell、RAG 信任边界、回调 |
| MCP server | [`mcp-server-security-scan`](./skills/defensive/genai/mcp-server-security-scan) | 工具 fs/exec/SSRF、传输层鉴权 |

Findings 格式: [`skills/SCORING.md`](./skills/SCORING.md)

### 进攻 — 对自有应用的自测 (`skills/offensive/`)

| 框架 / SDK | 技能 | 主要探测 |
|---|---|---|
| *(通用)* | [`webapp-pentest-checklist`](./skills/offensive/web/webapp-pentest-checklist) | OWASP Web/API Top 10 |
| Express | [`express-attack-probe`](./skills/offensive/web/express-attack-probe) | 原型污染、HPP、trust-proxy 伪造 |
| Django | [`django-attack-probe`](./skills/offensive/web/django-attack-probe) | DEBUG 泄漏、host 注入、DRF AllowAny、mass-assign |
| Spring Boot | [`spring-boot-attack-probe`](./skills/offensive/web/spring-boot-attack-probe) | actuator、h2-console、JWT 混淆、mass-assign |
| Next.js | [`nextjs-attack-probe`](./skills/offensive/web/nextjs-attack-probe) | NEXT_PUBLIC 泄漏、middleware 绕过、server action 鉴权 |
| FastAPI | [`fastapi-attack-probe`](./skills/offensive/web/fastapi-attack-probe) | OpenAPI 枚举、Depends 缺失、Pydantic 多余字段 |
| NestJS | [`nestjs-attack-probe`](./skills/offensive/web/nestjs-attack-probe) | ValidationPipe、Guard 缺失、WebSocket 鉴权 |
| *(通用)* | [`prompt-injection-probe`](./skills/offensive/genai/prompt-injection-probe) | 直接 / 间接 / 多轮 注入 |
| Anthropic SDK | [`anthropic-sdk-attack-probe`](./skills/offensive/genai/anthropic-sdk-attack-probe) | XML 标签混淆、prefill 滥用、tool input |
| OpenAI SDK | [`openai-sdk-attack-probe`](./skills/offensive/genai/openai-sdk-attack-probe) | function args、structured output 绕过、threads |
| Vercel AI SDK | [`vercel-ai-sdk-attack-probe`](./skills/offensive/genai/vercel-ai-sdk-attack-probe) | tool execute、useChat 鉴权、markdown XSS |
| LangChain | [`langchain-attack-probe`](./skills/offensive/genai/langchain-attack-probe) | REPL/Shell、RAG 注入、共享 memory |
| MCP server | [`mcp-server-attack-probe`](./skills/offensive/genai/mcp-server-attack-probe) | 路径穿越、传输层鉴权、SSRF、DNS rebinding |

探测约定: [`skills/PROBING.md`](./skills/PROBING.md)

## 快速开始

### Claude Code

将所需技能拷贝到项目作用域(推荐)或用户作用域:

```bash
# 项目作用域(随代码版本管理)
git clone https://github.com/Dolphinllc/claude-security-skills.git /tmp/css
mkdir -p .claude/skills
cp -r /tmp/css/skills/defensive/web/nextjs-security-scan .claude/skills/

# 用户作用域(所有项目可用)
cp -r /tmp/css/skills/defensive/web/nextjs-security-scan ~/.claude/skills/
```

下次启动 Claude Code 会自动发现技能。可通过 `/<skill-name>` 显式调用,或当 `description` 与任务匹配时由 Claude 自动触发。

### Claude Agent SDK

参照 [Agent SDK 文档](https://docs.claude.com/en/api/agent-sdk),将 `skills/` 目录挂载为技能源。

## 进攻技能的授权前置

每个进攻技能都遵循 [`skills/PROBING.md`](./skills/PROBING.md):

- 默认目标为 `localhost`、`127.0.0.1`、`*.localhost`,其余主机需要会话内明确确认。
- 目标端口由 env (`PORT`、`BASE_URL` 等) 或项目入口 (`package.json`、`Dockerfile`、`application.yml` 等) 解析得到,**不硬编码**。
- 不做 DoS、大规模凭证爆破、第三方系统、检测规避。
- 单次扫描的请求预算有上限,结果以结构化 schema 返回。

如果上述任一条件不满足,技能会返回单条 `PREFLIGHT-BLOCKED` finding 并立即停止。

## 参与贡献

欢迎提 PR。详见 [CONTRIBUTING.md](./CONTRIBUTING.md)。一条技能可以合入的标准:

1. 解决具体的防御或进攻课题(不是泛泛的安全综述)。
2. `description` 足够具体,Claude 能据此自我选择。
3. 至少包含一组 错误 vs. 正确 的代码示例。
4. 引用权威来源 (OWASP、NIST、厂商文档、CVE 等)。

## 许可证

[MIT](./LICENSE) © Dolphin LLC

## 维护方

[Dolphin LLC](https://github.com/Dolphinllc)
