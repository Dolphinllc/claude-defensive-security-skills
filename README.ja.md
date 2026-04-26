# Claude Defensive Security Skills

[Claude Code](https://docs.claude.com/ja/docs/claude-code) および [Claude Agent SDK](https://docs.claude.com/ja/api/agent-sdk) 向けの **防御的セキュリティスキル** 集です。**モダンな Web アプリケーション**と**生成 AI システム**の保護にフォーカスしています。

これらのスキルは、コードのハードニング、レビュー、インシデント対応のための再利用可能なプレイブックを Claude に与えます。攻撃側(オフェンシブ)の手法は扱いません。

## なぜ必要か

防御的セキュリティの知見は OWASP チートシート、ベンダードキュメント、ポストモーテムに散在しており、Claude にコードレビューや設計をさせるたびに毎回ゼロから探し直すことになります。スキルとしてパッケージ化することで、オンデマンドかつバージョン管理された形で必要なときだけ呼び出せるようになります。

スコープは意図的に絞っています:

- **Web**: OWASP Top 10、モダンな認証 (OAuth/OIDC、セッション/JWT)、CSRF/XSS/SSRF、サプライチェーン、ヘッダ/CSP、レート制限。
- **生成 AI**: プロンプトインジェクション対策、出力フィルタリング、RAG セキュリティ、エージェントのサンドボックス化、シークレット/PII の漏洩防止、モデル悪用対策。

スコープ外: レッドチーム用ツール、エクスプロイト開発、検知回避手法。

## ディレクトリ構成

```
skills/
├── web/         # Web アプリケーションの防御
└── genai/       # 生成 AI / LLM アプリケーションの防御
```

各スキルはディレクトリで管理され、YAML フロントマター付きの `SKILL.md` と、必要に応じて補助スクリプト・参考資料を含みます。

## スキルの使い方

### Claude Code で使う

スキルディレクトリをプロジェクトの `.claude/skills/` (プロジェクトスコープ) もしくは `~/.claude/skills/` (ユーザースコープ) にコピーします:

```bash
cp -r skills/web/csp-hardening ~/.claude/skills/
```

次回起動時に Claude Code が自動で検出します。`/<skill-name>` で明示的に呼び出すか、`description` がタスクと合致した場合に Claude が自動で起動します。

### Claude Agent SDK で使う

`skills/` ディレクトリをツールソースとしてマウントしてください。最新のローダ API は [Agent SDK のドキュメント](https://docs.claude.com/ja/api/agent-sdk) を参照してください。

## スキルのフォーマット

すべてのスキルは Anthropic 公式のスキル規約に従います:

```markdown
---
name: skill-name
description: いつ・なぜこのスキルを使うか (Claude が自己選択するため、具体的に書くこと)。
---

# Skill body

実行可能で具体的なガイダンス。散文よりチェックリスト・コードパターン・反例を優先する。
```

## コントリビューション

プルリクエスト歓迎です。マージ可能なスキルの条件:

1. 具体的な防御課題を解いていること (汎用的なセキュリティ概論ではないこと)。
2. `description` が十分に具体的で、Claude が自己選択できること。
3. **悪い例 vs. 良い例**のコードを最低 1 つ含むこと。
4. 一次情報源 (OWASP、NIST、ベンダーアドバイザリ等) を引用していること。

## ライセンス

MIT — [LICENSE](./LICENSE) を参照。

## メンテナ

[Dolphin LLC](https://github.com/Dolphinllc)

---

🇬🇧 English version: [README.md](./README.md)
