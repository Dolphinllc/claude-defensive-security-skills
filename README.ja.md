<div align="center">

# Claude Security Skills

[English](./README.md) · **日本語** · [简体中文](./README.zh-CN.md)

[Claude Code](https://docs.claude.com/ja/docs/claude-code) および [Claude Agent SDK](https://docs.claude.com/ja/api/agent-sdk) 向けの、プロダクション品質の **防御 (defensive)** と **攻撃 (offensive)** セキュリティスキル集です。

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](./CONTRIBUTING.md)
[![Skills](https://img.shields.io/badge/skills-25-blue)](./skills)

</div>

---

## 概要

[Claude Skills](https://docs.claude.com/ja/docs/agents-and-tools/agent-skills/overview)(Claude が必要なときだけオンデマンドで読み込む、バージョン管理されたプレイブック)を、**モダン Web アプリケーション**と**生成 AI システム**のハードニングのために整備したものです。

2 系統で構成しています:

- **防御 (`scan`)** — コードベースを与えると Claude が設定不備を検出し、重大度と 0–100 のスコア付きで構造化された findings を返します。各フレームワーク固有のイディオムに沿っています。
- **攻撃 (`probe`)** — 自分が所有する**起動中**のアプリに対して、レート制限と認可ゲート付きで一連のテストを実行し、実際に再現できた問題を報告します。ターゲットのポートは必ず環境変数 / エントリーポイントから解決し、ハードコードしません。

スコープ外: 第三者システムへのレッドチーム、エクスプロイト開発、検知回避、大規模スキャン。

## スキル一覧

### 防御 — コードレビュー & スコアリング (`skills/defensive/`)

| フレームワーク / SDK | スキル | 主な検出対象 |
|---|---|---|
| Next.js | [`nextjs-security-scan`](./skills/defensive/web/nextjs-security-scan) | env 漏洩、server actions、middleware、CORS、CSP |
| Express | [`express-security-scan`](./skills/defensive/web/express-security-scan) | middleware 順序、helmet、jwt、sendFile traversal |
| Django / DRF | [`django-security-scan`](./skills/defensive/web/django-security-scan) | DEBUG、raw ORM、mark_safe、AllowAny、`fields="__all__"` |
| Spring Boot | [`spring-boot-security-scan`](./skills/defensive/web/spring-boot-security-scan) | permitAll、CSRF、JdbcTemplate、Jackson、actuator |
| FastAPI | [`fastapi-security-scan`](./skills/defensive/web/fastapi-security-scan) | Depends、JWT、Pydantic、SQL、path traversal |
| NestJS | [`nestjs-security-scan`](./skills/defensive/web/nestjs-security-scan) | ValidationPipe、Guard、DTO、TypeORM raw |
| OpenAPI | [`openapi-spec-security-scan`](./skills/defensive/web/openapi-spec-security-scan) | global security、schema tightness、response 漏洩 |
| Anthropic SDK | [`anthropic-sdk-security-scan`](./skills/defensive/genai/anthropic-sdk-security-scan) | プロンプトインジェクション、tool input、prompt-cache の PII |
| OpenAI SDK | [`openai-sdk-security-scan`](./skills/defensive/genai/openai-sdk-security-scan) | function args、structured output、Assistants thread |
| Vercel AI SDK | [`vercel-ai-sdk-security-scan`](./skills/defensive/genai/vercel-ai-sdk-security-scan) | tool execute、attachments、streamText XSS |
| LangChain | [`langchain-security-scan`](./skills/defensive/genai/langchain-security-scan) | REPL/Shell、RAG trust、callbacks |
| MCP server | [`mcp-server-security-scan`](./skills/defensive/genai/mcp-server-security-scan) | tool fs/exec/SSRF、transport auth |

Findings フォーマット: [`skills/SCORING.md`](./skills/SCORING.md)

### 攻撃 — 自身のアプリに対する self-pentest (`skills/offensive/`)

| フレームワーク / SDK | スキル | 主なプローブ |
|---|---|---|
| *(汎用)* | [`webapp-pentest-checklist`](./skills/offensive/web/webapp-pentest-checklist) | OWASP Web/API Top 10 |
| Express | [`express-attack-probe`](./skills/offensive/web/express-attack-probe) | prototype pollution、HPP、trust-proxy 偽装 |
| Django | [`django-attack-probe`](./skills/offensive/web/django-attack-probe) | DEBUG 漏洩、host インジェクション、DRF AllowAny、mass-assign |
| Spring Boot | [`spring-boot-attack-probe`](./skills/offensive/web/spring-boot-attack-probe) | actuator、h2-console、JWT confusion、mass-assign |
| Next.js | [`nextjs-attack-probe`](./skills/offensive/web/nextjs-attack-probe) | NEXT_PUBLIC 漏洩、middleware bypass、server action 認証 |
| FastAPI | [`fastapi-attack-probe`](./skills/offensive/web/fastapi-attack-probe) | OpenAPI 列挙、Depends 漏れ、Pydantic 余剰フィールド |
| NestJS | [`nestjs-attack-probe`](./skills/offensive/web/nestjs-attack-probe) | ValidationPipe、Guard 漏れ、ws 認証 |
| *(汎用)* | [`prompt-injection-probe`](./skills/offensive/genai/prompt-injection-probe) | 直接 / 間接 / マルチターン インジェクション |
| Anthropic SDK | [`anthropic-sdk-attack-probe`](./skills/offensive/genai/anthropic-sdk-attack-probe) | XML タグ confusion、prefill 悪用、tool input |
| OpenAI SDK | [`openai-sdk-attack-probe`](./skills/offensive/genai/openai-sdk-attack-probe) | function args、structured output bypass、threads |
| Vercel AI SDK | [`vercel-ai-sdk-attack-probe`](./skills/offensive/genai/vercel-ai-sdk-attack-probe) | tool execute、useChat 認証、markdown XSS |
| LangChain | [`langchain-attack-probe`](./skills/offensive/genai/langchain-attack-probe) | REPL/Shell、RAG インジェクション、shared memory |
| MCP server | [`mcp-server-attack-probe`](./skills/offensive/genai/mcp-server-attack-probe) | path traversal、transport 認証、SSRF、DNS rebinding |

Probing 規約: [`skills/PROBING.md`](./skills/PROBING.md)

## クイックスタート

### Claude Code

必要なスキルをプロジェクトスコープ(推奨)またはユーザースコープに配置します:

```bash
# プロジェクトスコープ (コードと一緒にバージョン管理)
git clone https://github.com/Dolphinllc/claude-security-skills.git /tmp/css
mkdir -p .claude/skills
cp -r /tmp/css/skills/defensive/web/nextjs-security-scan .claude/skills/

# ユーザースコープ (全プロジェクトで利用可能)
cp -r /tmp/css/skills/defensive/web/nextjs-security-scan ~/.claude/skills/
```

次回起動時に Claude Code が自動検出します。`/<skill-name>` で明示的に呼ぶか、`description` がタスクと合致したときに Claude が自動で起動します。

### Claude Agent SDK

[Agent SDK のドキュメント](https://docs.claude.com/ja/api/agent-sdk) に従い、`skills/` ディレクトリをスキルソースとしてマウントしてください。

## 攻撃スキル使用時の認可ルール

すべての攻撃スキルは [`skills/PROBING.md`](./skills/PROBING.md) に従います:

- デフォルトのターゲットは `localhost`、`127.0.0.1`、`*.localhost`。それ以外のホストは明示確認が必要。
- ポートは env (`PORT`、`BASE_URL` 等) もしくはプロジェクトのエントリーポイント (`package.json`、`Dockerfile`、`application.yml` 等) から解決。**ハードコードしない**。
- DoS、大規模なクレデンシャル試行、第三者システム、検知回避は対象外。
- 1 スキャンあたりのリクエスト予算に上限を設け、結果は構造化スキーマで返却。

これらが満たせない場合は `PREFLIGHT-BLOCKED` finding 1 件を返して停止します。

## コントリビューション

PR 歓迎です。詳細は [CONTRIBUTING.md](./CONTRIBUTING.md)。マージ条件は:

1. 具体的な防御 / 攻撃課題を解いていること(汎用論ではない)。
2. `description` が Claude の自己選択に十分な具体性を持つこと。
3. 悪い例 vs. 良い例 のコードを最低 1 つ含むこと。
4. 一次情報源 (OWASP、NIST、ベンダードキュメント、CVE 等) を引用していること。

## ライセンス

[MIT](./LICENSE) © Dolphin LLC

## メンテナ

[Dolphin LLC](https://github.com/Dolphinllc)
