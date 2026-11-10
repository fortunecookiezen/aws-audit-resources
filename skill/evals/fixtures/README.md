# Eval fixtures

Everything in this directory is **synthetic**. It was written for the skill's eval suite (`../evals.json`) and describes no real AWS account. It is checked in deliberately. The rule in `../../references/evidence-handling.md`, that real snapshots, findings and reports never enter this repo, doesn't apply to it.

- **Account IDs** are AWS's documentation placeholders (`111122223333`, `444455556666`, `777788889999`).
- **Names and contacts** (`acme-*` resources, people, `example.com` addresses) are invented.
- **Credentials:** there are none. ARNs, key IDs and dates have the right shape so the checks evaluate them, but nothing here is a working credential. `partial-iam-credential-report.csv` has the columns of an IAM credential report, so a secret scanner that matches on keywords near ID-like strings could flag it. It contains no keys or passwords.

| File | Used by | What it is |
|---|---|---|
| `sample-snapshot.json` | eval 0 (CIS) | A snapshot of the six core areas with common failures: root MFA off, root access key, a public bucket, open SSH, a single-region trail. |
| `wa-sample-snapshot.json` | eval 1 (Well-Architected) | A mostly healthy account with a few real gaps: RDP open to `::/0`, a stale key, virtual root MFA. |
| `partial-iam-credential-report.csv` | eval 2 (SOC 2) | An IAM credential report alone, to test reporting on partial data. |
| `soc2-extended-snapshot.json` | eval 3 (SOC 2) | The core sample plus every newer section: detection services, databases, KMS, secrets, EBS, ECR, SNS. |
| `soc2-regions-snapshot.json`, `engagement-info-regions.md` | eval 4 (SOC 2) | The extended snapshot collected from three regions, with us-east-1 declared the only operating region and stray resources in eu-west-1. |
| `soc2-passing-snapshot.json`, `exceptions-passing.json` | eval 5 (SOC 2) | The regions snapshot after remediation. It passes: two Lows are risk-accepted, one administrator is by design, and the other regions hold only AWS defaults. |

The later snapshots were derived from earlier ones by small, deliberate edits; check a new or changed fixture with `run_checks.py` against its eval's expectations. Keep everything here synthetic: never copy real collector output into this directory, even redacted.
