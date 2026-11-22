# Policy-based filtering with CVSS and EPSS

Grype supports filtering SBOM (and image/directory) scan results by a risk
policy expressed through CVSS base scores and EPSS exploitation probabilities.
Filtered findings are recorded as **ignored matches** rather than dropped, so
every finding stays auditable in the JSON report.

## Threshold policy

The `policy` configuration block (and matching CLI flags) defines the minimum
risk a match must have to remain in the reported `matches` list:

| Field | CLI flag | Range | Meaning |
| --- | --- | --- | --- |
| `policy.min-cvss` | `--min-cvss` | 0–10 | minimum highest CVSS base score |
| `policy.min-epss` | `--min-epss` | 0–1 | minimum highest EPSS probability |
| `policy.exclude-missing-cvss` | `--exclude-missing-cvss` | bool | also suppress matches with no usable CVSS score |
| `policy.exclude-missing-epss` | `--exclude-missing-epss` | bool | also suppress matches with no EPSS data |

A threshold of `0` (the default) disables that check. When a threshold is set,
matches without the corresponding score data are **kept** unless the matching
`exclude-missing-*` option is enabled. This prevents a gap in upstream data
from silently hiding findings.

The highest score across all CVSS sources (v2/v3/v4) and all EPSS records is
used for the comparison. Threshold comparisons are inclusive: a match exactly
at the threshold is kept.

### Configuration example

```yaml
policy:
  min-cvss: 7.0
  min-epss: 0.1
  exclude-missing-cvss: false
  exclude-missing-epss: false
```

### CLI example

```bash
grype sbom:./sbom.json --min-cvss 7 --min-epss 0.1 -o json
```

Invalid ranges (CVSS outside 0–10, EPSS outside 0–1) fail fast with an
`invalid application config` error before any scanning starts.

## Ignore-rule score conditions

For fine-grained control, individual ignore rules accept score ceilings. A
match meeting every condition in the rule is ignored:

| Field | Meaning |
| --- | --- |
| `max-cvss` | ignore matches whose highest CVSS base score is below the value; missing scores count as 0 |
| `max-epss` | ignore matches whose highest EPSS probability is below the value; missing scores count as 0 |

These compose with the existing rule conditions (vulnerability ID, namespace,
package, fix state, match type, ...).

```yaml
ignore:
  # tolerate low-risk findings on a specific package
  - package:
      name: openssl
    max-cvss: 4.0
    max-epss: 0.05
    reason: accepted risk per security policy 2026-04
```

Unlike the threshold policy, ignore rules treat missing score data as a score
of `0`, so a positive ceiling also matches findings without score data.

## JSON output

Use `-o json` (or `output: json` in configuration) to emit the full document:

- `matches` contains findings that passed every policy and ignore rule.
- `ignoredMatches` contains suppressed findings, each with an
  `appliedIgnoreRules` array explaining why.

Threshold-policy suppressions use synthetic rules whose `reason` starts with
`policy-cvss-threshold:` or `policy-epss-threshold:`, including the observed
score and the configured threshold. Ignore-rule suppressions serialize the
rule, including any `max-cvss` / `max-epss` fields.

Example excerpt:

```json
{
  "ignoredMatches": [
    {
      "appliedIgnoreRules": [
        {
          "reason": "policy-cvss-threshold: CVSS base score 5.0 is below minimum 7.0"
        }
      ]
    }
  ]
}
```

## Comparison over many SBOMs

The offline test `TestPolicyFilterAcross100SBOMs`
(`grype/policy_sbom_bench_test.go`) runs the full matching → ignore-rule →
CVSS/EPSS policy → JSON pipeline across 100 synthetic SBOMs and compares a
no-policy baseline against several policies, asserting that every finding is
preserved (kept + ignored) and that suppression counts match a fixed profile.
Run it with:

```bash
go test ./grype/ -run TestPolicyFilterAcross100SBOMs -v
```
