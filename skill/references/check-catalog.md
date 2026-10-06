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
| `s3_block_public_access` | S3 | Critical | 3.1.4 | SEC03-BP07 | CC6.1, CC6.6 | A.5.15 |
| `s3_bucket_https_only` | S3 | Medium | 3.1.1 | SEC08-BP04 | CC6.7 | A.8.24 |
| `s3_bucket_mfa_delete` | S3 | Low | 3.1.2 | SEC08-BP04 | CC6.7 | A.8.24 |
| `s3_bucket_logging_enabled` | S3 | Medium | 4.8, 4.9 | SEC04-BP01 | CC7.1 | A.8.15 |
| `cloudtrail_multi_region_enabled` | Logging | Critical | 4.1 | SEC04-BP01 | CC7.1, CC7.2 | A.8.15 |
| `cloudtrail_log_file_validation` | Logging | Medium | 4.2 | SEC04-BP01 | CC7.1 | A.5.28 |
| `cloudtrail_bucket_access_logging` | Logging | Medium | 4.4 | SEC04-BP02 | CC6.1 | A.8.15 |
| `cloudtrail_kms_encryption` | Logging | Medium | 4.5 | SEC04-BP01 | CC6.1 | A.8.24 |
| `vpc_flow_logs_enabled` | SG/VPC | Medium | 4.7 | SEC04-BP01 | CC7.2 | A.8.16 |
| `sg_no_open_admin_ports_ipv4` | SG/VPC | Critical | 6.3 | SEC05-BP02 | CC6.1, CC6.6 | A.8.20 |
| `sg_no_open_admin_ports_ipv6` | SG/VPC | Critical | 6.4 | SEC05-BP02 | CC6.1, CC6.6 | A.8.20 |
| `sg_default_restricts_traffic` | SG/VPC | Low | 6.5 | SEC05-BP01 | CC6.1 | A.8.20 |
| `ec2_imdsv2_required` | SG/VPC | Medium | 6.7 | SEC05-BP02 | CC6.1 | A.8.20 |

26 checks total, all within the six core areas (IAM, MFA, S3, CloudTrail/logging, Security Groups/VPC, root account).

¹ Supports `--exceptions` — can resolve to `"pass"` (root checks, including `iam_credentials_unused_45d` for the root row only, via AWS Organizations centralized root access management) or `"accepted"` (`iam_no_full_admin_policy`, via a named admin-principal match) instead of `"fail"`. A root-management claim is only applied when it's corroborated by the actual collected data (no login profile, no access keys, no MFA device) — see `references/exceptions-and-exclusions.md`.

## Manual/extended checks (not automated in v1)

These controls appear in the frameworks above but are not evaluated by `run_checks.py` in this version — they require either a human judgment call, infrastructure outside the six core areas, or data this skill's collector does not gather. List them in the report's "Scope & Methodology" appendix as out-of-scope rather than silently omitting them.

- **CIS 2.2** — Maintain current AWS account contact details (needs human judgment on "current/correct", not just "populated")
- **CIS 2.21** — Resource policies don't allow unrestricted access via `Principal: *` (spans services outside the six core areas: SQS, SNS, Lambda, KMS, Secrets Manager)
- **CIS 5.2, 5.3, 5.5, 5.10** — CloudWatch metric-filter/alarm monitoring controls (require chained metric filter → alarm → confirmed SNS subscription checks; deferred to a future version)
- **CIS 6.6** — VPC peering route table least-access (inherently architectural/judgment-based)
- **CIS 6.8** — VPC Endpoints used for AWS service access (architectural; no automated Prowler-equivalent check exists yet either)

## Severity scale

`Critical` > `High` > `Medium` > `Low`. Used to order the "Key Findings" section of the report and to compute the findings summary's `by_severity` breakdown in `run_checks.py`.

## Status values

Each finding has a `status` of `"pass"`, `"fail"`, or `"accepted"`. `"accepted"` means the underlying fact is still true and still shown in the report, but an auditor has explicitly risk-accepted it via an `--exceptions` file rather than it being an open issue — see `references/exceptions-and-exclusions.md`. `root_mfa_enabled`, `root_hardware_mfa`, and `root_not_used_routinely` can also resolve to an ordinary `"pass"` (not `"accepted"`) when root credentials are centrally managed via AWS Organizations, either auto-detected from the snapshot's `organization` data or attested in the exceptions file; `iam_no_full_admin_policy` is the one check that can produce `"accepted"`, for a specific named role/user/group matched against `accepted_admin_principals`.
