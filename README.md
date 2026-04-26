# Claude Defensive Security Skills

Defensive security skills for [Claude Code](https://docs.claude.com/en/docs/claude-code) and the [Claude Agent SDK](https://docs.claude.com/en/api/agent-sdk), focused on protecting **modern web applications** and **generative AI systems**.

These skills equip Claude with reusable, opinionated playbooks for hardening code, reviewing changes, and responding to incidents — *without* offensive tradecraft.

## Why

Defensive security knowledge is scattered across OWASP cheat sheets, vendor docs, and incident postmortems. When Claude reviews code or designs a system, that knowledge has to be re-discovered every session. Skills package it as on-demand, version-controlled context.

Scope is intentionally narrow:

- **Web**: OWASP Top 10, modern auth (OAuth/OIDC, session/JWT), CSRF/XSS/SSRF, supply chain, headers/CSP, rate limiting.
- **Generative AI**: prompt injection defense, output filtering, RAG security, agent sandboxing, secret/PII leakage, model abuse.

Out of scope: red-team tooling, exploit development, evasion techniques.

## Repository layout

```
skills/
├── web/         # Web application defense
└── genai/       # Generative AI / LLM application defense
```

Each skill is a directory containing a `SKILL.md` (with YAML frontmatter) plus any supporting scripts or references.

## Using a skill

### With Claude Code

Copy a skill directory into your project's `.claude/skills/` (project scope) or `~/.claude/skills/` (user scope):

```bash
cp -r skills/web/csp-hardening ~/.claude/skills/
```

Claude Code auto-discovers the skill on next launch. Invoke it explicitly with `/<skill-name>` or let Claude trigger it when its `description` matches the task.

### With the Claude Agent SDK

Mount the `skills/` directory as a tool source — see the [Agent SDK docs](https://docs.claude.com/en/api/agent-sdk) for the current loader API.

## Skill format

Every skill follows the Anthropic skill convention:

```markdown
---
name: skill-name
description: When and why to use this skill (be specific — Claude reads this to decide).
---

# Skill body

Concrete, runnable guidance. Prefer checklists, code patterns, and counter-examples over prose.
```

## Contributing

Pull requests welcome. A skill is ready to merge when it:

1. Solves a concrete defensive problem (not a generic security overview).
2. Has a `description` precise enough for Claude to self-select it.
3. Includes at least one **wrong vs. right** code example.
4. Cites authoritative sources (OWASP, NIST, vendor advisories).

## License

MIT — see [LICENSE](./LICENSE).

## Maintainer

[Dolphin LLC](https://github.com/Dolphinllc)
