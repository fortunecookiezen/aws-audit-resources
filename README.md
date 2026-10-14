# aws-audit-resources

Tools for auditing the security configuration of AWS accounts: a read-only cross-account audit role, and an audit skill that collects an account's configuration, evaluates it against CIS AWS Foundations Benchmark, AWS Well-Architected Security Pillar, SOC 2, or ISO/IEC 27001, and produces a Word report. The skill can be run by Claude or by hand.

This repository is public and holds only tooling. Audit evidence never goes in it — see [Where audit data lives](#where-audit-data-lives).

## What's here

- [`skill/`](skill/SKILL.md) - the audit skill: `SKILL.md` (the procedure), `scripts/` (collector, checks, report builder, evidence and archive scripts), `references/` (framework mappings, check catalog, exceptions, retesting and evidence handling)
- [`cloudformation/`](cloudformation/README.md) - CloudFormation templates for cross-account security audit and incident-response roles, IAM Access Analyzer, and AWS Config
- [`terraform/`](terraform/README.md) - Terraform modules that create the same resources as the CloudFormation templates
- [`cloudshell/`](cloudshell/README.md) - setup for using AWS CloudShell as an audit workstation
- [`scripts/`](scripts/README.md) - useful commands for ad hoc audit work (assuming the audit role, CloudWatch queries, listing policies)
- `tag_release.sh` - tags a release of the tooling (maintainers; see [Releases](#releases))

## Requirements

- **AWS CLI** v2, and credentials that can assume the audit role in the target account (typically through IAM Identity Center)
- **Python 3.10 or newer**, in a virtual environment, with `skill/requirements.txt` installed (boto3, python-docx). On macOS, `/usr/bin/python3` is Apple's 3.9; use Homebrew's Python (see `skill/SKILL.md`, Step 2).
- **jq** - used by the evidence scripts and the role-assumption commands
- **git** - to check out a release and record the tool version for each run
- **age** or **gpg** - only to close out an engagement into an encrypted archive (`brew install age`, or an existing GPG key)
- **Optional:** Microsoft Word or LibreOffice, to read and check the generated report (building it doesn't need either)
- **Optional:** [Claude Code](https://claude.com/claude-code), to run the audit as a Claude skill

## Running an audit

### 1. Deploy the audit role (once per account)

Deploy [`cloudformation/security-audit-role.yml`](cloudformation/README.md) or the [`terraform/security-audit-role/`](terraform/README.md) module into the account to be audited. It creates a read-only `<org_prefix>-CrossAccountSecurityAuditRole` that your identity can assume.

### 2. Get the tool at a release

```bash
git clone https://github.com/fortunecookiezen/aws-audit-resources.git
cd aws-audit-resources
git checkout v0.1.0              # the release you'll audit with
git describe --always --dirty    # record this in the engagement's Testing Narrative
```

Use this checkout only to run audits. Findings depend on the code as well as the account, so audit from a release, and develop the tool in a separate clone (see [Developing the tool](#developing-the-tool)).

### 3. Set up Python

```bash
cd skill
/opt/homebrew/bin/python3 -m venv .venv   # Homebrew on Apple silicon; python3 on Linux. Must be 3.10+
source .venv/bin/activate
pip install -r requirements.txt
```

### 4. Run the audit

**With Claude.** Make the skill available to Claude Code by linking it into your skills directory, then ask Claude to audit the account:

```bash
ln -s "$PWD" ~/.claude/skills/aws-audit   # run from the skill/ directory
```

A link, rather than a copy, keeps the skill at the checked-out release and lets it record the tool version. Claude follows `skill/SKILL.md`: confirming the framework, creating the engagement directory, the documentation request, collection, checks, the report, retests and finalizing.

**By hand.** Follow [`skill/SKILL.md`](skill/SKILL.md) step by step. In outline, from `skill/`:

```bash
export AUDIT_DIR=~/audits/<client>/<account_id>-<YYYYMMDD>    # outside this checkout
mkdir -p "$AUDIT_DIR/evidence"
cp references/engagement-info-template.md "$AUDIT_DIR/engagement-info.md"
# send references/documentation-request-template.md to the account owner,
# and transcribe the response into $AUDIT_DIR/exceptions.json

export AUDIT_ROLE_ARN=arn:aws:iam::<account_id>:role/<org_prefix>-CrossAccountSecurityAuditRole
export AUDIT_SESSION_NAME="<auditor>-<YYYYMMDD>"
python3 scripts/collect_aws_data.py --all-regions --role-arn "$AUDIT_ROLE_ARN" \
  --role-session-name "$AUDIT_SESSION_NAME" -o "$AUDIT_DIR/snapshot.json"
python3 scripts/run_checks.py "$AUDIT_DIR/snapshot.json" --framework soc2 \
  --exceptions "$AUDIT_DIR/exceptions.json" -o "$AUDIT_DIR/findings.json"
python3 scripts/build_report.py "$AUDIT_DIR/findings.json"
```

| Stage | Where it's described |
|---|---|
| Scope, engagement directory, documentation request | `SKILL.md` Step 1; [`documentation-request-template.md`](skill/references/documentation-request-template.md) |
| Collection | `SKILL.md` Step 2 |
| Checks and exceptions | `SKILL.md` Step 3; [`exceptions-and-exclusions.md`](skill/references/exceptions-and-exclusions.md), [`accepting-findings-process.md`](skill/references/accepting-findings-process.md) |
| Report | `SKILL.md` Step 4 |
| Remediation, retests, finalizing | `SKILL.md` Steps 5-6; [`remediation-and-retesting.md`](skill/references/remediation-and-retesting.md) |
| Close-out and archive | [`evidence-handling.md`](skill/references/evidence-handling.md), "Closing out an engagement" |

### 5. Close out the engagement

When the report is `FINAL`, archive the engagement and remove the local copies:

```bash
bash scripts/archive_engagement.sh "$AUDIT_DIR" --age-recipient <age public key> --out-dir <dir>
# or, for an engagement kept in a private git repository:
bash scripts/archive_engagement.sh "$AUDIT_DIR" --manifest-only
```

Then store the archive, test a restore, and record it in your engagement register, per [`evidence-handling.md`](skill/references/evidence-handling.md).

## Where audit data lives

A real audit run produces evidence with real account data in it: account IDs, IAM principals, bucket names, and findings about where the account is weak. That evidence never belongs in this repo. Write each engagement into its own directory outside the tool checkout (for example `~/audits/<client>/<account_id>-<YYYYMMDD>/`), and when the report is final, close it out into a private engagement repository (a new repository, not a fork of this one) or an encrypted archive. `audit-runs/` at this repo's root is gitignored as a backstop, not as the place for engagements. See [`skill/references/evidence-handling.md`](skill/references/evidence-handling.md).

## Developing the tool

Work in a clone separate from the one you audit with, on a branch, through pull requests. Never put real account data in commits, pull requests or test fixtures: use the documentation placeholder account IDs `111122223333` and `444455556666`, and check a diff for real identifiers before pushing. Test data for the skill's eval suite is synthetic and lives in `skill/evals/fixtures/`.

## Releases

Audits run from a release tag, and each engagement records the tag it used. After merging changes to `main`, a maintainer tags a release:

```bash
./tag_release.sh 0.1.0    # creates and pushes v0.1.0
```

The script refuses to run with uncommitted or untracked files, or if the tag already exists, and tags the newest commit on `origin/main`. Bump the minor version for any change that can change a finding (checks, the collector, the exceptions logic), the major version for a change to the snapshot or findings file formats, and the patch version for documentation and report-layout changes.

## Security scanning

This repo is scanned with GitGuardian. `.gitguardian.yaml` excludes `skill/evals/fixtures/` from secret scanning — that directory is synthetic test data for the skill's eval suite (see [`skill/evals/fixtures/README.md`](skill/evals/fixtures/README.md) for why it can still look like a credential report to a keyword-proximity detector). Nothing else in this repo is excluded; a finding anywhere else should be treated as real until shown otherwise.
