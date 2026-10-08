---
name: aws-audit
description: Audits an AWS account's security configuration against CIS AWS Foundations Benchmark, AWS Well-Architected Security Pillar, SOC 2, or ISO/IEC 27001, and produces a Word document report. Use when the user asks to audit, assess, or review AWS account security — including requests mentioning CIS, Well-Architected, SOC2/SOC 2, ISO27001/ISO 27001, IAM hygiene, root account/MFA, S3 public access, CloudTrail/logging, or security group exposure.
---

# AWS Account Security Audit

Audits the six core technical areas of an AWS account's security posture — IAM, MFA, S3 bucket security, CloudTrail/logging, Security Groups/VPC exposure, and root account protections — against one compliance framework at a time, and produces a Word document report of findings.

This skill lives inside the `aws-audit-resources` repository, alongside the IAM role templates (`cloudformation/`, `terraform/`) that provide the actual cross-account access the live-data path below uses. If you are working inside a checkout of that repo, the role templates referenced in Step 2 are at `../cloudformation/security-audit-role.yml` and `../terraform/security-audit-role/` relative to this skill directory.

**Before collecting any real account data**, create a per-engagement working directory at the repo root — `audit-runs/<account_id>-<YYYYMMDD>/` (e.g. `../audit-runs/111122223333-20261006/` relative to this skill directory) — as part of Step 1, and write `engagement-info.md`, `exceptions.json`, the snapshot, findings, and report there, not into the repo's tracked directories. That path is covered by this repo's `.gitignore` for exactly this reason. See `references/evidence-handling.md` for the full clone → audit → evidence → private-repo-or-archive lifecycle, including what to do with the working directory once the audit is done. Fixture data under `skill/evals/` is synthetic and exempt from this — it's checked in deliberately, see `evals/fixtures/README.md`.

## Step 1: Confirm framework and scope

Ask the user which framework to audit against if not already specified:
- **CIS** — CIS AWS Foundations Benchmark v7.0.0 (default if the user doesn't specify)
- **Well-Architected** — AWS Well-Architected Framework, Security Pillar
- **SOC2** — SOC 2 Trust Services Criteria (Common Criteria / Security category)
- **ISO27001** — ISO/IEC 27001:2022 Annex A

Confirm the scope is the six core areas listed above. This skill does not audit RDS, EFS, EBS, KMS-general, AWS Config, AWS Organizations governance, Security Hub/GuardDuty enablement, or other services outside those six areas — if the user wants broader coverage, note that it's out of scope for this version rather than guessing at checks that don't exist yet.

Create the engagement directory and its `engagement-info.md` now, from this skill directory:
```bash
mkdir -p ../audit-runs/<account_id>-<YYYYMMDD>
cp references/engagement-info-template.md ../audit-runs/<account_id>-<YYYYMMDD>/engagement-info.md
```

If this account's expected exceptions aren't already known (centrally-managed root credentials, named admin roles, other pre-reviewed risks), send the account/engagement owner `references/documentation-request-template.md` now rather than waiting to correct false positives after the report is built — see `references/accepting-findings-process.md`. When it comes back, save it in the engagement directory as `documentation-request-response.md` (or the signed PDF, `documentation-request-response.pdf`), and put its attachments — `list-organizations-features` output, console screenshots, tickets — under `evidence/` there. Then transcribe it into `exceptions.json` in the same directory, section by section, using the mapping in `references/exceptions-and-exclusions.md` ("From the documentation request"). `exceptions.json` is optional: if there are no exceptions, don't create it, and leave `--exceptions` off in Step 3.

Fill in `engagement-info.md` with what's known (report status starts `DRAFT`, account/engagement owner, primary contact; leave auditor fields blank if the auditor wants to fill those in directly rather than have them guessed). `scripts/build_report_final.js` reads this file for the report's cover-page author block, DRAFT/FINAL labeling, and Testing Narrative table — see Step 4 and `references/remediation-and-retesting.md`.

## Step 2: Get the account data

The account data this skill evaluates can come from any of three sources. Pick whichever the user has available.

### A. Live AWS access via the repo's CrossAccountSecurityAuditRole (preferred when available)

This repo's `cloudformation/security-audit-role.yml` (or the equivalent `terraform/security-audit-role/` module) deploys a dedicated, read-only `<org_prefix>-CrossAccountSecurityAuditRole` into the target account specifically for this kind of review. It grants exactly four AWS-managed policies (`SecurityAudit`, `job-function/ViewOnlyAccess`, `AmazonInspector2ReadOnlyAccess`, `AWSSecurityHubReadOnlyAccess`) plus a narrow `SupplementalReadOnlyAccess` inline policy covering a handful of gaps those managed policies leave (notifications, IAM Access Analyzer, GuardDuty/Macie/Shield/WAFv2 describe-level access, CloudTrail's `ListEventDataStores`, billing/account contact visibility, `sts:GetCallerIdentity`, which `collect_aws_data.py` calls first to verify the assumed role before collecting anything else, and `organizations:DescribeOrganization`/`iam:ListOrganizationsFeatures`/`iam:ListEntitiesForPolicy` (`OrganizationsRootAccessContext` Sid), which let the collector detect AWS Organizations centralized root access management when run with the right privileges and enumerate which specific roles/users hold an admin-wildcard policy — see `references/exceptions-and-exclusions.md`). It does not grant write access to anything.

1. **If the role isn't deployed in the target account yet**, deploy it first — either:
   - `aws cloudformation deploy --template-file ../cloudformation/security-audit-role.yml --stack-name security-audit-role --parameter-overrides PrincipalAccountId=<centralized-account-id> TrustedPrincipalArnPattern=<sso-permission-set-arn-pattern> Owner=<owner-email> --capabilities CAPABILITY_NAMED_IAM`, or
   - the equivalent `terraform/security-audit-role/` module (see `terraform/README.md` for the module-call example).

   `RequireMFA` should stay `false` if the auditor signs in through IAM Identity Center (SSO) — Identity Center sessions never carry `aws:MultiFactorAuthPresent`, so `true` would lock every SSO user out of the role. See `cloudformation/README.md` for the full trust-policy rationale.

2. **Assume the role** from a session already authenticated in the trusted/centralized account (matching the pattern in `scripts/README.md`):
   ```bash
   export AUDIT_ROLE_ARN="arn:aws:iam::<target-account-id>:role/<org_prefix>-CrossAccountSecurityAuditRole"
   eval $(aws sts assume-role --role-arn $AUDIT_ROLE_ARN \
     --role-session-name audit-session | jq -r '.Credentials | "export AWS_ACCESS_KEY_ID=\(.AccessKeyId)\nexport AWS_SECRET_ACCESS_KEY=\(.SecretAccessKey)\nexport AWS_SESSION_TOKEN=\(.SessionToken)\n"')
   ```
   Alternatively, pass `--role-arn` directly to `collect_aws_data.py` (see below) and let it assume the role itself via `boto3.client('sts').assume_role(...)` rather than exporting credentials into the shell.

3. **Run the collector, writing into the engagement directory created in Step 1:**
   ```bash
   # Python >= 3.10 required (macOS's /usr/bin/python3 is 3.9 — use Homebrew/pyenv/uv Python).
   # Use a venv rather than installing into the system/Homebrew Python.
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   python3 scripts/collect_aws_data.py --all-regions -o ../audit-runs/<account_id>-<YYYYMMDD>/snapshot.json
   # or, to have the script assume the role itself instead of pre-exporting credentials:
   python3 scripts/collect_aws_data.py --all-regions --role-arn $AUDIT_ROLE_ARN -o ../audit-runs/<account_id>-<YYYYMMDD>/snapshot.json
   ```

### B. Exported files

If the user has already exported account configuration (from the AWS console, Config, or another tool), build a JSON file matching `collect_aws_data.py`'s output schema by hand — see the script's docstring and the field names referenced throughout `references/check-catalog.md` for what each check expects.

### C. AWS connector/MCP

If an AWS MCP connector is available in this session, use it to gather the equivalent data points (IAM credential report, account summary, S3 public-access-block settings, CloudTrail trail configuration, security groups, EC2 instance metadata options) and assemble them into the same JSON schema before proceeding to Step 3.

## Step 3: Run the checks

```bash
python3 scripts/run_checks.py ../audit-runs/<account_id>-<YYYYMMDD>/snapshot.json \
  --framework cis -o ../audit-runs/<account_id>-<YYYYMMDD>/findings.json
# --framework ∈ {cis, well_architected, soc2, iso27001, all}
```

This produces a findings list plus a summary (total findings, pass/fail/accepted counts, breakdown by severity, checks evaluated vs. skipped due to missing data). If a data source is partial (e.g., only an IAM credential report, no S3/CloudTrail/EC2 data), checks that can't be evaluated are marked skipped rather than guessed at — be honest in the report about what wasn't checked rather than implying full coverage.

A few checks (root MFA/access-keys/routine-use/unused-credentials, full-admin IAM policies) can produce false positives that aren't visible from the collected data alone — a root user with credentials centrally removed via AWS Organizations, or a deliberately-named admin role. Before treating those findings as real issues, check whether `--exceptions ../audit-runs/<account_id>-<YYYYMMDD>/exceptions.json` applies; see `references/exceptions-and-exclusions.md` for the file format and what it does (and doesn't) auto-detect, and `references/accepting-findings-process.md` for the process behind deciding what belongs in it:

```bash
python3 scripts/run_checks.py ../audit-runs/<account_id>-<YYYYMMDD>/snapshot.json \
  --framework cis --exceptions ../audit-runs/<account_id>-<YYYYMMDD>/exceptions.json \
  -o ../audit-runs/<account_id>-<YYYYMMDD>/findings.json
```

`exceptions.json` can also accept a specific failing finding for any other check (a public website bucket, an intentionally open port) through `accepted_findings` rules, which need an approver and a `review_by` date — see `references/exceptions-and-exclusions.md`. Read every `WARNING:` line `run_checks.py` prints (also saved in `summary.exceptions_warnings`): it flags rules that were refused, have expired, match nothing, or look too broad.

## Step 4: Build the report

Read the docx skill's SKILL.md, then build a Word document with this structure:

1. **Cover page** — title, framework, a DRAFT/FINAL status banner and matching cover-table row, a "Prepared By" author block, and the Testing Narrative table (Test Start, Test Completion, Findings Draft, Findings Review, Findings Completion). All of this is sourced from `engagement-info.md` (see Step 1) — don't hand-write it per report. Every report is titled `DRAFT`, in the cover banner, the page header, and the output filename, until the explicit finalization step (Step 6); only `engagement-info.md`'s `Report Status` field changes that, and it changes all four at once.
2. **Executive Summary** — account(s) audited, framework, overall posture, headline numbers
3. **Key Findings** — critical/high findings first, grouped by area
4. **Accepted Findings** (only if `--exceptions` was used and produced any) — findings with status `"accepted"`: the underlying fact, who accepted it and why (from the exceptions file's `note`), and the matching rule. Keep these visibly separate from both Key Findings and Passing Controls — they're neither an open issue nor a clean pass, they're a reviewed, deliberate acceptance.
5. **Passing Controls** — brief list, so the report isn't only bad news
6. **Detailed Findings by Area** — one subsection per core area (IAM, MFA, S3, CloudTrail/Logging, Security Groups/VPC, Root Account), each finding with control reference(s) for the chosen framework, evidence, and remediation
7. **Appendix: Scope & Methodology** — which six areas were in scope, which controls were evaluated vs. skipped (including the "manual/extended checks" list from `references/check-catalog.md`), data source used, date of collection, and whether an exceptions file was applied (and if so, note its presence in the evidence package per Step 3)

Write the report into the same `audit-runs/<account_id>-<YYYYMMDD>/` directory as the snapshot and findings — once the audit is complete, that whole directory is the evidence package. Follow `references/evidence-handling.md` for what to do with it next (a private evidence repo or an archive, never this repo).

## Step 5: Remediate and retest

The audit doesn't end at the report. When findings get fixed, don't take anyone's word for it — re-collect fresh data and re-run the checks, and diff the new findings against the baseline rather than eyeballing the two summary counts (a fix and a regression can net out to the same pass/fail total). Full procedure, including when a full retest vs. a targeted one is appropriate and how to handle a finding that's real but doesn't map to the audited framework's controls, is in `references/remediation-and-retesting.md`. The mechanical diff itself is `scripts/diff_findings.py findings-baseline.json findings-retest.json`.

## Step 6: Finalize the report

A report only becomes `FINAL` through this explicit step — never by editing the cover page directly, and never automatically just because remediation activity has stopped. In short: confirm every open finding is either fixed-and-retested or formally accepted, fill in the last two Testing Narrative rows and any blank auditor fields in `engagement-info.md`, set `Report Status: FINAL`, and rebuild — the cover banner, page header, and output filename all flip from `DRAFT` to `FINAL` automatically from that one field. Keep every superseded `DRAFT` in the evidence package rather than deleting it. Full procedure is in `references/remediation-and-retesting.md`'s "Finalizing" section.

## Reference files

- `references/engagement-info-template.md` — the per-engagement file format (copy to `engagement-info.md`) for author data, Report Status (DRAFT/FINAL), and the Testing Narrative table that `scripts/build_report_final.js` renders onto the report cover page
- `references/check-catalog.md` — master table of all 27 automated checks with cross-framework control IDs (including which checks are best-practice-only, with no control in a given framework); keep in lockstep with `run_checks.py`'s `CHECKS_META`/`CHECK_FUNCS` and `collect_aws_data.py`'s collectors when extending
- `references/cis-aws-foundations.md` — full CIS AWS Foundations Benchmark v7.0.0 control reference (36 controls, six core areas)
- `references/well-architected-security.md` — AWS Well-Architected Security Pillar (SEC01–SEC08) mapping
- `references/soc2-mapping.md` — SOC 2 Trust Services Criteria (CC6.x/CC7.x) mapping
- `references/iso27001-mapping.md` — ISO/IEC 27001:2022 Annex A control mapping
- `references/evidence-handling.md` — what to do with a completed audit's output: the `audit-runs/` convention, and the private-repo-or-archive lifecycle for real evidence
- `references/exceptions-and-exclusions.md` — the `--exceptions` file format: correcting root-account findings for AWS Organizations centralized root access management, a configurable root-reuse review window, marking named admin roles as a reviewed risk acceptance rather than an open finding, and how a root-management claim gets corroborated against the actual data before it's applied
- `references/accepting-findings-process.md` — the governance process behind the exceptions file: who can accept a finding, what evidence they need, how a claim/data contradiction gets investigated, and how accepted findings get reviewed over time
- `references/documentation-request-template.md` — fill-in template to request known exceptions (admin roles, root-management status, other pre-reviewed risks) from the account/engagement owner before the audit runs
- `references/remediation-and-retesting.md` — the procedure for after the report ships: tracking remediation, re-collecting and re-running checks, diffing findings instead of trusting summary counts, and handling a real finding that doesn't map to the audited framework's controls (e.g. a region's default VPC)

## Scripts

- `scripts/collect_aws_data.py` — boto3 collector; supports `--profile`, `--role-arn`/`--role-session-name` (assume-role), `--regions`/`--all-regions`, `-o/--output`
- `scripts/run_checks.py` — evaluates a snapshot against one framework; `snapshot.json --framework {cis|well_architected|soc2|iso27001|all} [--exceptions exceptions.json] -o findings.json`
- `scripts/diff_findings.py` — compares a baseline and a retest findings.json per check/resource (not just summary counts) for the Step 5 remediation workflow; `findings-baseline.json findings-retest.json [-o diff.json]`
