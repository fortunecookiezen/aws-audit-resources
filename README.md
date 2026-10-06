# aws-audit-resources
miscellaneous resources for performing audit functions in aws accounts

- [`cloudformation/`](cloudformation/README.md) - CloudFormation templates for cross-account security audit and incident-response roles, IAM Access Analyzer, and AWS Config
- [`terraform/`](terraform/README.md) - Terraform modules that create the same resources as the CloudFormation templates
- [`skill/`](skill/SKILL.md) - Claude skill that audits an AWS account's security configuration against CIS AWS Foundations Benchmark, AWS Well-Architected Security Pillar, SOC 2, or ISO/IEC 27001, using the cross-account audit role above for live data access, and produces a Word document report

## Requirements

- jtbl
- jq
- aws-cli