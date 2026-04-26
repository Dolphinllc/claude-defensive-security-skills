# Contributing

Thanks for considering a contribution. This project ships **Claude Skills** — prompt-side artifacts that change Claude's behavior when loaded — so review focuses on whether the skill produces useful, safe behavior, not just whether the markdown parses.

## Quick checklist

A skill is ready to merge when:

- [ ] It solves a concrete defensive or offensive task (not a generic security overview).
- [ ] `description` in the YAML frontmatter is precise enough for Claude to self-select it. Bad: *"security helper"*. Good: *"Detects missing helmet, unsafe body-parser limits, ... in Express.js apps"*.
- [ ] At least one **wrong vs. right** code example.
- [ ] Cites authoritative sources (OWASP, NIST, vendor docs, CVE).
- [ ] For **defensive** skills: emits findings using [`skills/SCORING.md`](./skills/SCORING.md).
- [ ] For **offensive** skills: follows [`skills/PROBING.md`](./skills/PROBING.md) — authorization preflight, no hardcoded port (resolve from env / entrypoint), throttled, no out-of-scope behavior.
- [ ] No payloads that target third-party systems, attempt DoS, mass credential brute-force, persistence, lateral movement, or detection evasion.

## Out of scope

We won't accept skills covering:

- Exploitation of third-party systems.
- Working exploit chains (RCE beyond a benign `id`/`echo` to confirm the code path).
- Credential dumping, persistence, lateral movement, AV/EDR evasion.
- Mass scanning or DoS payloads.
- Anything that violates the [Anthropic Usage Policy](https://www.anthropic.com/legal/aup).

## Skill format

```markdown
---
name: my-skill-name
description: One sentence on when and why to invoke. Be specific — Claude reads this to self-select.
---

# Skill body

Concrete, runnable guidance. Prefer:
- Rule tables with IDs and severity
- Wrong-vs-right code blocks
- Authoritative references
```

Place the file at `skills/<defensive|offensive>/<web|genai>/<skill-name>/SKILL.md`.

## Adding a new framework

If you're adding a framework that doesn't exist yet, please contribute **both** a defensive scan **and** an offensive probe whenever feasible — they reinforce each other and the catalog is more useful when the pair is complete.

Use existing skills as templates:

- Defensive web: [`nextjs-security-scan`](./skills/defensive/web/nextjs-security-scan/SKILL.md)
- Defensive AI: [`anthropic-sdk-security-scan`](./skills/defensive/genai/anthropic-sdk-security-scan/SKILL.md)
- Offensive web: [`nextjs-attack-probe`](./skills/offensive/web/nextjs-attack-probe/SKILL.md)
- Offensive AI: [`langchain-attack-probe`](./skills/offensive/genai/langchain-attack-probe/SKILL.md)

## Translations

Top-level READMEs are kept in:

- `README.md` — English (source of truth)
- `README.ja.md` — Japanese
- `README.zh-CN.md` — Simplified Chinese

When you change `README.md`, please update the others or note in the PR description that translations need a follow-up. Skill bodies (`SKILL.md`) stay in English so Claude consistently reads them — translate the surrounding docs only.

## PR process

1. Open an issue first if the change is large (new framework, schema change). Quick fixes can go straight to PR.
2. Fork, branch from `main`, keep one logical change per PR.
3. Run a sanity check: paste your `description` to Claude in another project and verify the skill self-selects only when relevant.
4. We aim to review within a week.

## Code of Conduct

Be kind. Treat issues, PRs, and discussions as you would in a professional setting. Maintainers may close threads that go off-topic or hostile.
