# aws-audit-resources
miscellaneous resources for performing audit functions in aws accounts

- [`cloudformation/`](cloudformation/README.md) - CloudFormation templates for cross-account security audit and incident-response roles, IAM Access Analyzer, and AWS Config
- [`terraform/`](terraform/README.md) - Terraform modules that create the same resources as the CloudFormation templates
- [`skill/`](skill/SKILL.md) - Claude skill that audits an AWS account's security configuration against CIS AWS Foundations Benchmark, AWS Well-Architected Security Pillar, SOC 2, or ISO/IEC 27001, using the cross-account audit role above for live data access, and produces a Word document report

## Requirements

- jtbl
- jq
- aws-cli

## Running an audit? Read this first

A real audit run (`skill/scripts/collect_aws_data.py` against a live account) produces evidence with real account data in it — that evidence never belongs in this repo. Write it into a gitignored `audit-runs/<account_id>-<date>/` directory and move it to a private evidence repo or an archive when you're done. See [`skill/references/evidence-handling.md`](skill/references/evidence-handling.md).

## Security scanning

This repo is scanned with GitGuardian. `.gitguardian.yaml` excludes `skill/evals/fixtures/` from secret scanning — that directory is synthetic test data for the skill's eval suite (see [`skill/evals/fixtures/README.md`](skill/evals/fixtures/README.md) for why it can still look like a credential report to a keyword-proximity detector). Nothing else in this repo is excluded; a finding anywhere else should be treated as real until shown otherwise.