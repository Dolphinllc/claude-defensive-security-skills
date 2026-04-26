# Scoring Schema

All skills in this repo emit findings using this shared schema so results can be aggregated across scans.

## Output format

Claude returns a single YAML or JSON block at the end of a scan:

```yaml
scan: <skill-name>
target: <path or scope scanned>
findings:
  - id: <SKILL-CATEGORY-NNN>
    severity: critical | high | medium | low | info
    location: <relative/path.ts:line>
    rule: <short rule description>
    evidence: |
      <exact code snippet that triggered the rule>
    fix: <one-paragraph remediation, idiomatic to the library>
    refs:
      - <authoritative URL>
score: <0-100>
summary: "<N critical, N high, N medium, N low>"
notes: <optional caveats / false-positive risk>
```

## Severity weights

Used to compute the aggregate score. Lower score = riskier.

| Severity | Weight | When to use |
|----------|--------|-------------|
| critical | 25 | Direct, exploitable RCE / auth bypass / secret leak in prod path |
| high     | 10 | Likely-exploitable injection, missing authn/authz, unsafe deserialization |
| medium   | 4  | Defense-in-depth gap (missing header, weak default, partial validation) |
| low      | 1  | Hygiene issue, deprecated API |
| info     | 0  | Observation only, no security impact |

```
score = max(0, 100 - Σ(weight_i × count_i))
```

## Severity assignment rules

- **Default conservatively**: if exploitability depends on assumptions you cannot verify from the code alone, drop one level.
- **Promote on confirmation**: if you can trace user-controlled data into a sink within the same scan, promote one level.
- **Never use `critical` without evidence**: a `critical` finding must include the exact line where untrusted data reaches the dangerous sink.

## Anti-patterns to avoid

- ❌ Reporting style/lint issues as `low` — those belong in a linter, not a security scan.
- ❌ Assigning severity by rule name alone — context matters (a `dangerouslySetInnerHTML` on a static string is `info`, on user input is `high`).
- ❌ Inventing rule IDs — reuse the IDs defined in each skill's rule table.
- ❌ Reporting findings without `evidence` — every finding must quote the offending code.
