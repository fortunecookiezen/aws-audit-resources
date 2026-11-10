# Check Catalog

Master list of the automated checks this skill runs. Each row maps one `check_id` to its control references across the four supported frameworks. This table, `scripts/run_checks.py`'s `CHECKS_META`/`CHECK_FUNCS`, and `scripts/collect_aws_data.py`'s collectors must be kept in lockstep: adding a check means adding a row here, a `CHECKS_META` entry and a `CHECK_FUNCS` function, and (if new raw data is needed) a collector field.

| check_id | Area | Severity | CIS v7.0.0 | Well-Architected | SOC 2 | ISO 27001 |
|---|---|---|---|---|---|---|
| `root_mfa_enabled`¹ | Root | Critical | 2.5 | SEC01-BP02 | CC6.1, CC6.6 | A.8.5 |
| `root_hardware_mfa`¹ | Root | Medium | 2.6 | SEC01-BP02 | CC6.1 | A.8.5 |
| `root_no_access_keys`¹ | Root | Critical | 2.4 | SEC01-BP02 | CC6.1, CC6.3 | A.8.2 |
| `root_not_used_routinely`¹ | Root | High | 2.7 | SEC01-BP02 | CC6.3 | A.8.2 |
| `account_security_contact_registered` | Root | Low | 2.3 | SEC01-BP02 | CC6.2 | A.5.18 |
| `iam_password_policy_length` | IAM | Medium | 2.8 | SEC02-BP01 | CC6.1 | A.5.17 |
| `iam_password_policy_reuse` | IAM | Medium | 2.9 | SEC02-BP01 | CC6.1 | A.5.17 |
| `iam_user_mfa_console_access` | MFA | Critical | 2.10 | SEC02-BP01 | CC6.1, CC6.6 | A.8.5 |
| `iam_credentials_unused_45d`¹ | IAM | Medium | 2.11 | SEC02-BP05 | CC6.3 | A.5.18 |
| `iam_access_key_rotation_90d` | IAM | Medium | 2.12 | SEC02-BP05 | CC6.1 | A.5.17 |
| `iam_permissions_via_group_only` | IAM | Low | 2.13 | SEC02-BP06 | CC6.3 | A.5.15 |
| `iam_no_full_admin_policy`¹ | IAM | High | 2.14 | SEC03-BP02 | CC6.3 | A.5.15, A.8.2 |
| `iam_support_role_exists` | IAM | Low | 2.15 | SEC02-BP02 | CC6.2 | A.8.2 |
| `s3_block_public_access` | S3 | Critical³ | 3.1.4 | SEC03-BP07 | CC6.1, CC6.6 | A.5.15 |
| `s3_bucket_https_only` | S3 | Medium | 3.1.1 | SEC08-BP04 | CC6.7 | A.8.24 |
| `s3_bucket_mfa_delete` | S3 | Low | 3.1.2 | SEC08-BP04 | CC6.7 | A.8.24 |
| `s3_bucket_logging_enabled` | S3 | Medium | 4.8, 4.9 | SEC04-BP01 | CC7.1 | A.8.15 |
| `cloudtrail_multi_region_enabled` | Logging | Critical | 4.1 | SEC04-BP01 | CC7.1, CC7.2 | A.8.15 |
| `cloudtrail_log_file_validation` | Logging | Medium | 4.2 | SEC04-BP01 | CC7.1 | A.5.28 |
| `cloudtrail_bucket_access_logging`⁴ | Logging | Medium | 4.4 | SEC04-BP02 | CC6.1 | A.8.15 |
| `cloudtrail_kms_encryption` | Logging | Medium | 4.5 | SEC04-BP01 | CC6.1 | A.8.24 |
| `vpc_flow_logs_enabled` | SG/VPC | Medium | 4.7 | SEC04-BP01 | CC7.2 | A.8.16 |
| `sg_no_open_admin_ports_ipv4` | SG/VPC | Critical | 6.3 | SEC05-BP02 | CC6.1, CC6.6 | A.8.20 |
| `sg_no_open_admin_ports_ipv6` | SG/VPC | Critical | 6.4 | SEC05-BP02 | CC6.1, CC6.6 | A.8.20 |
| `sg_default_restricts_traffic` | SG/VPC | Low | 6.5 | SEC05-BP01 | CC6.1 | A.8.20 |
| `ec2_imdsv2_required` | SG/VPC | Medium | 6.7 | SEC05-BP02 | CC6.1 | A.8.20 |
| `default_vpc_exists`² | SG/VPC | Low | — | SEC05-BP01 | — | — |
| `guardduty_enabled`⁶ | Detection | High | — | SEC04-BP03 | CC7.2 | A.8.16 |
| `securityhub_enabled`⁶ | Detection | Medium | 5.16⁵ | SEC04-BP02 | CC7.2, CC7.3 | A.8.16 |
| `inspector_enabled`⁶ | Detection | Medium | — | SEC06-BP01 | CC7.1 | A.8.8 |
| `access_analyzer_enabled`⁶ | Detection | Medium | 2.20⁵ | SEC03-BP07 | CC6.1, CC6.3 | A.5.15 |
| `config_recorder_enabled`⁶ | Detection | Medium | 4.3⁵ | SEC04-BP01 | CC7.1, CC8.1 | A.8.9 |
| `cloudwatch_log_group_retention` | Detection | Low | — | SEC04-BP02 | CC7.2 | A.8.15 |
| `rds_instance_not_public` | Databases | High | 3.3.3⁵ | SEC05-BP01 | CC6.1, CC6.6 | A.8.20 |
| `rds_storage_encrypted`⁷ | Databases | High | 3.3.1⁵ | SEC08-BP02 | CC6.1 | A.8.24 |
| `rds_backup_retention_7d`⁷ | Databases | Medium | — | REL09-BP03⁸ | CC7.5, CC9.1 | A.8.13 |
| `rds_deletion_protection`⁷ | Databases | Low | — | REL09-BP01⁸ | CC7.5, CC9.1 | A.8.13 |
| `rds_snapshot_not_public` | Databases | Critical | — | SEC03-BP07 | CC6.1, CC6.6, CC6.7 | A.8.3, A.8.12 |
| `dynamodb_pitr_enabled` | Databases | Medium | — | REL09-BP03⁸ | CC7.5, CC9.1 | A.8.13 |
| `elasticache_encryption_at_rest` | Databases | Medium | — | SEC08-BP02 | CC6.1 | A.8.24 |
| `elasticache_encryption_in_transit` | Databases | Medium | — | SEC09-BP02 | CC6.7 | A.8.24 |
| `kms_cmk_rotation_enabled` | Encryption | Medium | 4.6⁵ | SEC08-BP01 | CC6.1 | A.8.24 |
| `secrets_rotation_enabled`⁹ | Encryption | Medium | — | SEC02-BP03 | CC6.1 | A.5.17 |
| `resource_policy_no_public_principal`¹⁰ | Encryption | High | 2.21 | SEC03-BP07 | CC6.1, CC6.3, CC6.6 | A.5.15, A.8.3 |
| `ebs_default_encryption`⁶ | Encryption | Medium | 3.2.1⁵ | SEC08-BP02 | CC6.1 | A.8.24 |
| `ebs_volume_encrypted` | Encryption | Medium | — | SEC08-BP02 | CC6.1 | A.8.24 |
| `ebs_snapshot_not_public` | Encryption | Critical | — | SEC03-BP07 | CC6.1, CC6.6, CC6.7 | A.8.3, A.8.12 |
| `ecr_image_scanning` | Containers | Medium | — | SEC06-BP01 | CC7.1 | A.8.8 |
| `ecr_tag_immutability` | Containers | Low | — | SEC11-BP06 | CC8.1 | A.8.32 |
| `resources_outside_operating_regions`¹¹ | Regional Footprint | Medium³ | — | —² | CC6.1 | A.5.9, A.8.3 |

50 checks total: 27 in the six core areas (IAM, MFA, S3, CloudTrail/logging, Security Groups/VPC, root account) and 23 in five further areas — Detection & Monitoring (GuardDuty, Security Hub, Inspector, IAM Access Analyzer, AWS Config, CloudWatch Logs), Databases (RDS, DynamoDB, ElastiCache), Encryption & Secrets (KMS, Secrets Manager, EBS, plus SNS and ECR resource policies), Containers (ECR) and Regional Footprint. A `—` in the CIS column of the new rows means the control isn't in CIS AWS Foundations; the check reports under `--framework cis` with that stated, the same way `default_vpc_exists` does.

¹ Supports `--exceptions` — can resolve to `"pass"` (root checks, including `iam_credentials_unused_45d` for the root row only, via AWS Organizations centralized root access management) or `"accepted"` (`iam_no_full_admin_policy`, via a named admin-principal match) instead of `"fail"`. Any other check can also resolve to `"accepted"` through an `accepted_findings` rule for a specific resource; the checks marked ¹ can't, because they have these stricter paths instead. A root-management claim is only applied when it's corroborated by the actual collected data (no login profile, no access keys, no MFA device) — see `references/exceptions-and-exclusions.md`.

² Best-practice-only check: no CIS AWS Foundations Benchmark v7.0.0, SOC 2, or ISO 27001 control specifically requires deleting a region's default VPC (the `—` cells above aren't missing data, they're "this framework doesn't have a control for this"). It still runs and is reported under every framework, with that absence stated plainly in the report rather than a fabricated control ID — see `references/remediation-and-retesting.md`, "Findings outside the audited framework's scope."

³ Critical by default, but a bucket whose own Block Public Access setting is missing or incomplete is rated **Low** when the account-level setting has all four flags on: the account-level setting overrides bucket settings, so the bucket can't be made public. It still fails 3.1.4, which requires both levels; the evidence says why it's Low. `resources_outside_operating_regions` also varies: Medium, or **High** when the region's resources are internet-exposed (see ¹¹). Separately, any region-level check becomes an Informational advisory outside the operating regions (see ⁶), and a Low finding with no control in the audited framework is rated Informational.

⁴ An organization trail's bucket is usually in another account (the management or log archive account), where the audit role's `s3:GetBucketLogging` is denied unless that bucket's policy allows it. The collector then records the call in `collection_errors` and leaves the trail's logging as unknown, so the check has no result for it and is marked incomplete; it isn't failed for logging the role couldn't read. To evaluate it, either have the bucket's owner allow the audit role `s3:GetBucketLogging` on the bucket, or collect the setting as evidence in the account that owns it and record it under `verified_values` in the exceptions file (see `exceptions-and-exclusions.md`).

⁵ CIS IDs for these controls follow the v3.0 → v7.0.0 renumbering visible in `cis-aws-foundations.md` (v3.0 1.20 → 2.20, 2.2.1 → 3.2.1, 2.3.1 → 3.3.1, 2.3.3 → 3.3.3, 3.3 → 4.3, 3.6 → 4.6, 4.16 → 5.16). Confirm them against the v7.0.0 benchmark document before citing them in a final report; `cis-aws-foundations.md` doesn't describe them yet.

⁶ Evaluated per collected region: each region is its own result, so an audit run with `--all-regions` reports every enabled region that lacks the service (CIS 4.3 and 2.20 ask for every region). Organization-wide GuardDuty, Security Hub, Inspector and Config still turn the service on in each member account and region, so a missing region is a real gap wherever the audit runs. When `engagement-info.md` declares Operating Regions, a failure in any other region is an **Informational advisory** instead of the check's own severity: the client doesn't operate there, but activity in an unused region would otherwise go unseen. The same applies to `default_vpc_exists`, `sg_default_restricts_traffic` and `vpc_flow_logs_enabled` for the default VPC and default security groups AWS creates in every region. A custom VPC or security group outside the operating regions keeps full severity. An attested `region_deny_scp` in the exceptions file turns those advisories into passes for the regions it denies, unless resources were found there (see `exceptions-and-exclusions.md`). Record Access Analyzer under `accepted_findings`, with evidence, when an ORGANIZATION analyzer in the management or delegated administrator account covers this account (that analyzer doesn't appear in the member account).

⁷ An instance that belongs to a cluster (Aurora, Multi-AZ DB cluster) takes its storage encryption, backup retention and deletion protection from the cluster, so the cluster is evaluated and its member instances aren't. `rds_instance_not_public` is evaluated per instance, since public accessibility is set per instance.

⁸ Backups and deletion protection are in the Well-Architected Reliability pillar, not the Security pillar this skill's Well-Architected framework covers; the ID is given so the finding still has a reference.

⁹ Secrets owned by another service (`OwningService` set — an RDS-managed master password, an EventBridge API destination connection) are left out: that service controls their rotation, so the customer can't turn it on. A secret that can't rotate automatically (a third-party API key) is a real finding; resolve it with a documented manual rotation process recorded under `accepted_findings`.

¹⁰ Covers KMS customer-managed key policies, Secrets Manager resource policies, ECR repository policies and SNS topic policies. A statement is public when it allows `Principal: "*"` (or `{"AWS": "*"}`, or uses `NotPrincipal`) and no condition key narrows it to specific accounts, organizations, sources or networks (`aws:PrincipalOrgID`, `aws:PrincipalAccount`, `aws:SourceAccount`, `aws:SourceArn`, `aws:SourceVpce`, `aws:SourceIp`, `kms:CallerAccount` and similar). The collector records only that answer, not the policy document. SQS queue, Lambda function and S3 bucket policies aren't covered yet (S3 public access is `s3_block_public_access`).

¹¹ Evaluated only when `engagement-info.md` declares Operating Regions (`- Operating Regions: us-east-1, us-east-2` under Report Metadata); otherwise it's skipped with that reason and every collected region is treated as operating. One result per collected region outside the operating regions: it passes when the region holds only AWS-created defaults (default VPC and security group, AWS-managed KMS keys, service-owned secrets), and fails when anything else is there — EC2 instances, custom VPCs and security groups, RDS instances, clusters and snapshots, DynamoDB tables, ElastiCache, customer-managed KMS keys, secrets, ECR repositories, SNS topics, EBS volumes, CloudWatch log groups, S3 buckets and single-region CloudTrail trails — whether or not those resources pass their own checks. It's **High** when a failing or accepted exposure check (`sg_no_open_admin_ports_ipv4`/`ipv6`, `rds_instance_not_public`, `rds_snapshot_not_public`, `ebs_snapshot_not_public`, `resource_policy_no_public_principal`, `s3_block_public_access`) is in the same region. The finding's evidence names up to 15 resources per region; the full list, with each resource's exposure and other findings, is in the finding's `resources` field, the report's "Resources Outside the Operating Regions" appendix, and one remediation-tracker row per resource. It's marked incomplete when an enabled region wasn't collected, so audit with `--all-regions`. Services the collector doesn't gather (Lambda, ECS, API Gateway, CodePipeline and others) aren't in the inventory. Neither CIS v7.0.0 nor the Well-Architected Security Pillar has a specific control for it.

## Manual/extended checks (not automated in v1)

These controls appear in the frameworks above but are not evaluated by `run_checks.py` in this version — they require either a human judgment call, infrastructure outside the areas above, or data this skill's collector does not gather. List them in the report's "Scope & Methodology" appendix as out-of-scope rather than silently omitting them.

- **CIS 2.2** — Maintain current AWS account contact details (needs human judgment on "current/correct", not just "populated")
- **CIS 2.21 (remainder)** — Resource policies don't allow unrestricted access via `Principal: *`: `resource_policy_no_public_principal` covers KMS, Secrets Manager, ECR and SNS; SQS queue and Lambda function policies still need a manual review
- **CIS 5.2, 5.3, 5.5, 5.10** — CloudWatch metric-filter/alarm monitoring controls (require chained metric filter → alarm → confirmed SNS subscription checks; deferred to a future version)
- **CIS 6.6** — VPC peering route table least-access (inherently architectural/judgment-based)
- **CIS 6.8** — VPC Endpoints used for AWS service access (architectural; no automated Prowler-equivalent check exists yet either)

## Severity scale

`Critical` > `High` > `Medium` > `Low` > `Informational`. Used to order the "Key Findings" section of the report, to compute the findings summary's `by_severity` breakdown in `run_checks.py`, and to decide the audit result.

No check is Informational by default. A finding becomes Informational in two cases: a region-level control or AWS-created default that fails outside the declared operating regions (an advisory, see ⁶), and a **Low** finding with no control in the audited framework (`default_vpc_exists` under SOC 2 or ISO 27001, for example). An unmapped finding at Medium or above keeps its severity, and the report labels it as outside the framework. Under CIS, for example, a public RDS snapshot is still Critical even though CIS doesn't cover RDS snapshots.

## Audit result

`run_checks.py` records an `audit_result` in the findings summary: **PASS** or **NOT PASSING**, the standard it applied, and every item that blocks a pass. Under the default standard an audit passes only when all of the following hold:

- **Critical, High and Medium findings are remediated.** They must pass in the collected data. A risk-accepted (`accepted_findings`) finding at these severities still blocks.
- **Low findings are remediated or risk-accepted** through `accepted_findings`.
- **Every applicable check was evaluated completely.** A check skipped for missing data, or incomplete because of a failed collection call, blocks a pass. A check skipped for another stated reason doesn't, such as `resources_outside_operating_regions` when no operating regions are declared.
- **Informational findings never block.** They're communicated to management, together with the accepted Lows.

A principal matched by `accepted_admin_principals` is an administrator by design, not a risk accepted in place of a fix, so it doesn't block a pass even though `iam_no_full_admin_policy` is High. It's still listed for management.

To change the standard, set `- Pass Criteria: <severity>` in `engagement-info.md`. It names the lowest severity that must be remediated: `Critical`, `High`, `Medium` (the default) or `Low`. Findings below it must be remediated or risk-accepted. With `High`, an accepted Medium no longer blocks; with `Low`, nothing can be accepted.

## Status values

Each finding has a `status` of `"pass"`, `"fail"`, or `"accepted"`. `"accepted"` means the underlying fact is still true and still shown in the report, but an auditor has explicitly risk-accepted it via an `--exceptions` file rather than it being an open issue — see `references/exceptions-and-exclusions.md`. `root_mfa_enabled`, `root_hardware_mfa`, and `root_not_used_routinely` can also resolve to an ordinary `"pass"` (not `"accepted"`) when root credentials are centrally managed via AWS Organizations, either auto-detected from the snapshot's `organization` data or attested in the exceptions file; `"accepted"` comes from either `accepted_admin_principals` (for `iam_no_full_admin_policy`, a specific named role/user/group) or an `accepted_findings` rule (any other check except the root checks, for a specific resource, with an approver and a review-by date).
