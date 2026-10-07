# CIS AWS Foundations Benchmark — Core-Scope Control Reference

**Benchmark version used:** CIS Amazon Web Services Foundations Benchmark **v7.0.0** (released April 2026 — the current version as of this writing, per CIS's own release announcement). Control numbering below is v7.0.0's.

**Version-lag note for the skill:** AWS-native tooling typically trails the newest CIS release by several months — AWS Security Hub CSPM added v5.0.0 support in October 2025 and had not yet announced v6.0.0/v7.0.0 support as of this document's compilation. If the skill needs to cross-reference Security Hub's CIS standard subscription or an AWS Config conformance pack, it may still be speaking v5.0.0/v4.0.1 numbering. A mapping table from v7.0.0 IDs back to v5.0.0 IDs is included in each section below (v5.0.0 was section `1.x` for IAM instead of `2.x`, `2.x` for Storage instead of `3.x`, etc. — v7.0.0 inserted a new front-matter section, shifting everything by one).

**Scope of this document:** only the six areas requested — (1) IAM users/policies/password policy/access keys, (2) MFA, (3) S3 bucket security, (4) CloudTrail/logging, (5) Security Groups/VPC exposure, (6) root account protections. Controls outside this scope (RDS, EFS, EBS, KMS-general, AWS Config, AWS Organizations governance, Security Hub enablement, GuardDuty, generic CloudWatch alarms not tied to one of the six areas) are intentionally omitted, **except** for a handful of CloudWatch metric-filter/alarm controls (section 5 "Monitoring" in CIS) that are the detective-control counterpart to root usage, MFA, security-group, and CloudTrail-config changes — these are marked **[bonus/monitoring]** below since they technically live in CIS's "Monitoring" section but are inseparable from the six requested areas in practice.

Every control below lists a `Checks:` line — this is the internal check-ID Prowler (the open-source CIS-AWS scanner) uses for that control, included because it's a useful cross-reference if the skill ever wants to validate its own logic against Prowler's implementation.

---

## Quick-reference table (all controls in scope)

| ID (v7.0.0) | v5.0.0 equiv. | Area | Level | Title |
|---|---|---|---|---|
| 2.2 | 1.1 | Root | 1 | Maintain current AWS account contact details |
| 2.3 | 1.2 | Root | 1 | Ensure security contact information is registered |
| 2.4 | 1.3 | Root | 1 | Ensure no 'root' user account access key exists |
| 2.5 | 1.4 | MFA | 1 | Ensure MFA is enabled for the 'root' user account |
| 2.6 | 1.5 | MFA | 2 | Ensure hardware MFA is enabled for the 'root' user account |
| 2.7 | 1.6 | Root | 1 | Eliminate use of the 'root' user for administrative and daily tasks |
| 2.8 | 1.7 | IAM | 1 | Ensure IAM password policy requires minimum length of 14+ |
| 2.9 | 1.8 | IAM | 1 | Ensure IAM password policy prevents password reuse |
| 2.10 | 1.9 | MFA | 1 | Ensure MFA is enabled for all IAM users with a console password |
| 2.11 | 1.11 | IAM | 1 | Ensure credentials unused for 45+ days are disabled |
| 2.12 | 1.13 | IAM | 1 | Ensure access keys are rotated every 90 days or less |
| 2.13 | 1.14 | IAM | 1 | Ensure IAM users receive permissions only through groups |
| 2.14 | 1.15 | IAM | 1 | Ensure IAM policies allowing full `*:*` admin privileges are not attached |
| 2.15 | 1.16 | IAM | 1 | Ensure a support role has been created to manage AWS Support incidents |
| 2.21 | *(new in v7.0.0)* | IAM / S3 | 1 | Ensure resource policies don't allow unrestricted access via `Principal: *` |
| 3.1.1 | 2.1.1 | S3 | 2 | Ensure S3 bucket policy denies HTTP (non-TLS) requests |
| 3.1.2 | 2.1.2 | S3 | 2 | Ensure MFA Delete is enabled on S3 buckets |
| 3.1.4 | 2.1.4 | S3 | 1 | Ensure S3 Block Public Access is enabled (account + bucket) |
| 4.1 | 3.1 | Logging | 1 | Ensure CloudTrail is enabled in all regions |
| 4.2 | 3.2 | Logging | 2 | Ensure CloudTrail log file validation is enabled |
| 4.4 | 3.4 | Logging | 1 | Ensure server access logging is enabled on the CloudTrail S3 bucket |
| 4.5 | 3.5 | Logging | 2 | Ensure CloudTrail logs are encrypted at rest using KMS CMKs |
| 4.7 | 3.7 | SG/VPC | 2 | Ensure VPC flow logging is enabled in all VPCs |
| 4.8 | 3.8 | S3 / Logging | 2 | Ensure S3 object-level logging for write events is enabled |
| 4.9 | 3.9 | S3 / Logging | 2 | Ensure S3 object-level logging for read events is enabled |
| 5.2 | 4.2 | MFA [bonus] | 1 | Ensure console sign-in without MFA is monitored |
| 5.3 | 4.3 | Root [bonus] | 1 | Ensure usage of the 'root' account is monitored |
| 5.5 | 4.5 | Logging [bonus] | 1 | Ensure CloudTrail configuration changes are monitored |
| 5.10 | 4.10 | SG/VPC [bonus] | 2 | Ensure security group changes are monitored |
| 6.2 | 5.2 | SG/VPC | 1 | Ensure no NACL allows ingress from 0.0.0.0/0 to admin ports (22/3389) |
| 6.3 | 5.3 | SG/VPC | 1 | Ensure no security group allows ingress from 0.0.0.0/0 to admin ports |
| 6.4 | 5.4 | SG/VPC | 1 | Ensure no security group allows ingress from ::/0 to admin ports |
| 6.5 | 5.5 | SG/VPC | 2 | Ensure the default security group of every VPC restricts all traffic |
| 6.6 | 5.6 | SG/VPC | 2 | Ensure VPC peering route tables are "least access" |
| 6.7 | 5.7 | SG/VPC | 1 | Ensure EC2 Metadata Service only allows IMDSv2 |
| 6.8 | *(new in v7.0.0)* | SG/VPC | 2 | Ensure VPC Endpoints are used for access to AWS services |

36 controls total, all within the six requested areas.

---

## 1. IAM — users, policies, password policy, access keys

### 2.8 — Ensure IAM password policy requires a minimum length of 14+
- **Level:** 1 | **Checks:** `iam_password_policy_minimum_length_14`
- **Pass/Fail:** Pass if the account password policy's `MinimumPasswordLength` is ≥ 14. Fail if no password policy exists at all (AWS default has no minimum), or the minimum is set lower.
- **AWS CLI:**
  ```bash
  aws iam get-account-password-policy
  # check: PasswordPolicy.MinimumPasswordLength >= 14
  # a "NoSuchEntity" error means no policy is set at all => automatic fail
  ```
- **Remediation:** `aws iam update-account-password-policy --minimum-password-length 14` (combine with the other password-policy flags in one call rather than issuing multiple).

### 2.9 — Ensure IAM password policy prevents password reuse
- **Level:** 1 | **Checks:** `iam_password_policy_reuse_24`
- **Pass/Fail:** Pass if `PasswordReusePrevention` is set to 24 or more previous passwords. Fail if unset or less than 24.
- **AWS CLI:**
  ```bash
  aws iam get-account-password-policy
  # check: PasswordPolicy.PasswordReusePrevention >= 24
  ```
- **Remediation:** `aws iam update-account-password-policy --password-reuse-prevention 24`.

### 2.11 — Ensure credentials unused for 45+ days are disabled
- **Level:** 1 | **Checks:** `iam_user_accesskey_unused`, `iam_user_console_access_unused`
- **Pass/Fail:** Pass if every IAM user's console password and every access key has been used within the last 45 days (or was never used but is younger than 45 days). Fail if `password_last_used` or `access_key_N_last_used_date` is more than 45 days in the past, or a credential has never been used and is older than 45 days.
- **AWS CLI:**
  ```bash
  aws iam generate-credential-report            # kick off report generation (may need a retry loop)
  aws iam get-credential-report --query Content --output text | base64 -d > credreport.csv
  # parse columns: password_last_used, access_key_1_last_used_date, access_key_2_last_used_date,
  # access_key_1_active, access_key_2_active, user_creation_time
  ```
- **Remediation:** Deactivate the access key (`aws iam update-access-key --status Inactive`) or disable/remove the console password (`aws iam delete-login-profile`) for any credential idle 45+ days; delete the IAM user entirely if it's no longer needed.

### 2.12 — Ensure access keys are rotated every 90 days or less
- **Level:** 1 | **Checks:** `iam_rotate_access_key_90_days`
- **Pass/Fail:** Pass if every active access key's age (from `access_key_N_last_rotated`, or creation date if never rotated) is ≤ 90 days. Fail otherwise.
- **AWS CLI:**
  ```bash
  aws iam get-credential-report            # same CSV as above; use access_key_N_last_rotated
  # or per-user: aws iam list-access-keys --user-name <user>   (CreateDate field)
  ```
- **Remediation:** Create a new access key, update the application/service to use it, then delete or deactivate the old key: `aws iam create-access-key` → `aws iam delete-access-key`.

### 2.13 — Ensure IAM users receive permissions only through groups
- **Level:** 1 | **Checks:** `iam_policy_attached_only_to_group_or_roles`
- **Pass/Fail:** Pass if no IAM user has any policy (managed or inline) attached directly. Fail if any user has a directly attached managed policy or an inline policy — permissions should flow only via group membership.
- **AWS CLI:**
  ```bash
  aws iam list-users
  # for each user:
  aws iam list-attached-user-policies --user-name <user>   # should return empty
  aws iam list-user-policies --user-name <user>             # inline policies, should return empty
  ```
- **Remediation:** Create an IAM group with the equivalent policy attached, add the user to the group with `aws iam add-user-to-group`, then remove the direct/inline policy from the user.

### 2.14 — Ensure IAM policies allowing full `*:*` admin privileges are not attached
- **Level:** 1 | **Checks:** `iam_aws_attached_policy_no_administrative_privileges`, `iam_customer_attached_policy_no_administrative_privileges`
- **Pass/Fail:** Pass if no managed policy (AWS-managed or customer-managed) that is currently attached to any user/group/role contains a statement with `"Effect": "Allow"`, `"Action": "*"`, `"Resource": "*"`. Fail if such a policy is attached anywhere (e.g., `AdministratorAccess` attached broadly, or a custom equivalent).
- **AWS CLI:**
  ```bash
  aws iam list-policies --scope All --only-attached
  # for each policy:
  aws iam get-policy --policy-arn <arn>                              # get DefaultVersionId
  aws iam get-policy-version --policy-arn <arn> --version-id <ver>    # inspect Document.Statement
  # flag Statement entries where Effect=Allow, Action includes "*", Resource includes "*"
  aws iam list-entities-for-policy --policy-arn <arn>                # who it's attached to
  ```
- **Remediation:** Detach the overly-broad policy from the user/group/role and replace it with a least-privilege custom policy scoped to the specific actions/resources actually required.

### 2.15 — Ensure a support role has been created to manage AWS Support incidents
- **Level:** 1 | **Checks:** `iam_support_role_created`
- **Pass/Fail:** Pass if the AWS-managed `AWSSupportAccess` policy is attached to at least one IAM role. Fail if it isn't attached anywhere, which forces admins to use highly-privileged credentials just to open a support case.
- **AWS CLI:**
  ```bash
  aws iam list-policies --scope AWS --query "Policies[?PolicyName=='AWSSupportAccess']"
  aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess --entity-filter Role
  # PolicyRoles should be non-empty
  ```
- **Remediation:** Create a dedicated IAM role with a trust policy allowing the appropriate principals to assume it, and attach the `AWSSupportAccess` managed policy.

### 2.21 — Ensure resource policies don't allow unrestricted access via `Principal: *` *(new in v7.0.0)*
- **Level:** 1 | **Checks:** `s3_bucket_policy_public_write_access`, `sqs_queues_not_publicly_accessible`, `sns_topics_not_publicly_accessible`, `awslambda_function_not_publicly_accessible`, `kms_key_not_publicly_accessible`, `glacier_vaults_policy_public_access`, `secretsmanager_not_publicly_accessible`, `eventbridge_bus_exposed`
- **Pass/Fail:** Pass if every resource-based policy (S3 bucket policy, SQS queue policy, SNS topic policy, Lambda resource policy, KMS key policy, Secrets Manager resource policy, etc.) either avoids `"Principal": "*"` entirely, or pairs it with a restrictive `Condition` (e.g., `aws:PrincipalOrgID`, `aws:SourceArn`, `aws:SourceVpce`) that limits the effective grantee. Fail if any resource policy grants `"Effect": "Allow"` to `"Principal": "*"` with no meaningfully restrictive condition.
- **AWS CLI:**
  ```bash
  aws s3api get-bucket-policy --bucket <bucket> --query Policy --output text | jq .
  aws sqs get-queue-attributes --queue-url <url> --attribute-names Policy
  aws sns get-topic-attributes --topic-arn <arn>            # Attributes.Policy
  aws lambda get-policy --function-name <fn>                # Policy field (may 404 if none)
  aws kms get-key-policy --key-id <key-id> --policy-name default
  aws secretsmanager get-resource-policy --secret-id <id>
  # for each: parse Statement[] for Principal == "*" (or {"AWS":"*"}) AND Effect == Allow, then
  # check whether Condition meaningfully restricts the caller
  ```
- **Remediation:** Replace the wildcard `Principal` with specific account/role/service ARNs, or keep the wildcard but add a `Condition` (org ID, source VPC endpoint, source ARN) that restricts who can actually use the grant.

**IAM controls covered by MFA (2.10) or root account (2.4, 2.7) sections below are cross-referenced there, not duplicated here.**

---

## 2. MFA — root and IAM users

### 2.5 — Ensure MFA is enabled for the root user account
- **Level:** 1 | **Checks:** `iam_root_mfa_enabled`
- **Pass/Fail:** Pass if the root account has any MFA device (virtual or hardware) enabled. Fail if it has none — this is one of the highest-severity findings in any CIS AWS audit.
- **AWS CLI:**
  ```bash
  aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'
  # 1 = enabled, 0 = not enabled
  ```
- **Remediation:** Sign in as root (only root can manage its own MFA) and attach a virtual or hardware MFA device via IAM console → Security Credentials.

### 2.6 — Ensure hardware MFA is enabled for the root user account
- **Level:** 2 | **Checks:** `iam_root_hardware_mfa_enabled`
- **Pass/Fail:** Pass if root's MFA device is a physical/hardware token (or FIDO security key) rather than a virtual (app-based, e.g. authenticator app) device. Fail if root has no MFA, or only a virtual MFA device.
- **AWS CLI:**
  ```bash
  aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'   # must be 1 first
  aws iam list-virtual-mfa-devices --assignment-status Assigned \
    --query "VirtualMFADevices[?User.Arn=='arn:aws:iam::<ACCOUNT_ID>:root']"
  # if AccountMFAEnabled=1 but root does NOT show up in the virtual-devices list,
  # its device is hardware/FIDO => pass. If it does show up => virtual => fail (for Level 2).
  ```
- **Remediation:** Remove the virtual MFA device from root and register a hardware MFA token (or FIDO security key) instead, since it must be done from a root sign-in.

### 2.10 — Ensure MFA is enabled for all IAM users with a console password
- **Level:** 1 | **Checks:** `iam_user_mfa_enabled_console_access`
- **Pass/Fail:** Pass if every IAM user that has a console login profile also has at least one MFA device assigned. Fail if any user with `password_enabled=true` shows `mfa_active=false`.
- **AWS CLI:**
  ```bash
  aws iam generate-credential-report
  aws iam get-credential-report --query Content --output text | base64 -d > credreport.csv
  # columns of interest: password_enabled, mfa_active
  # or per-user: aws iam get-login-profile --user-name <u> (exists?) + aws iam list-mfa-devices --user-name <u>
  ```
- **Remediation:** Have the user (or an admin on their behalf) register a virtual or hardware MFA device via `aws iam enable-mfa-device` or the IAM console.

### 5.2 — Ensure console sign-in without MFA is monitored **[bonus/monitoring]**
- **Level:** 1 | **Checks:** `cloudwatch_log_metric_filter_sign_in_without_mfa`
- **Pass/Fail:** Pass if a CloudWatch Logs metric filter exists on the CloudTrail log group matching non-MFA console sign-in events, *and* that metric has a CloudWatch alarm with at least one active SNS subscriber. Fail if the filter, the alarm, or the working subscription is missing.
- **AWS CLI:**
  ```bash
  aws cloudtrail describe-trails --query 'trailList[].CloudWatchLogsLogGroupArn'
  aws logs describe-metric-filters --log-group-name <cloudtrail-log-group>
  # look for a filterPattern matching ConsoleLogin events where additionalEventData.MFAUsed != "Yes"
  aws cloudwatch describe-alarms --query "MetricAlarms[?MetricName=='<metric-name-from-filter>']"
  aws sns list-subscriptions-by-topic --topic-arn <alarm-action-topic-arn>
  ```
- **Remediation:** Create the metric filter with `aws logs put-metric-filter`, then `aws cloudwatch put-metric-alarm` pointing at an SNS topic that has a confirmed subscriber.

---

## 3. S3 bucket security — public access, encryption, logging

### 3.1.1 — Ensure S3 bucket policy denies HTTP (non-TLS) requests
- **Level:** 2 | **Checks:** `s3_bucket_secure_transport_policy`
- **Pass/Fail:** Pass if the bucket policy contains a `Deny` statement that applies to all principals/actions when `aws:SecureTransport` is `false`. Fail if no such deny statement exists (S3 permits both HTTP and HTTPS by default).
- **AWS CLI:**
  ```bash
  aws s3api get-bucket-policy --bucket <bucket> --query Policy --output text | jq .
  # look for Statement: Effect=Deny, Condition.Bool."aws:SecureTransport"="false"
  ```
- **Remediation:** Attach/merge a bucket policy statement such as `{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::bucket","arn:aws:s3:::bucket/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}`.

### 3.1.2 — Ensure MFA Delete is enabled on S3 buckets
- **Level:** 2 | **Checks:** `s3_bucket_no_mfa_delete`
- **Pass/Fail:** Pass if the bucket has versioning enabled *and* `MFADelete` is `Enabled`. Fail if versioning is off or MFA Delete is not enabled — this only matters for sensitive/critical buckets.
- **AWS CLI:**
  ```bash
  aws s3api get-bucket-versioning --bucket <bucket>
  # check: Status == "Enabled" and MFADelete == "Enabled"
  ```
- **Remediation:** MFA Delete can only be toggled by the root user via CLI/API (not the console): `aws s3api put-bucket-versioning --bucket <bucket> --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa "arn:aws:iam::ACCOUNT:mfa/root-account-mfa-device MFA_CODE"`.

### 3.1.4 — Ensure S3 Block Public Access is enabled (account + bucket)
- **Level:** 1 | **Checks:** `s3_bucket_level_public_access_block`, `s3_account_level_public_access_blocks`
- **Pass/Fail:** Pass if both the account-level and every bucket-level Block Public Access setting have all four flags (`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`) set to `true`. Fail if any flag is `false` at either level, or the setting is entirely absent.
- **AWS CLI:**
  ```bash
  aws s3control get-public-access-block --account-id <account-id>
  aws s3api get-public-access-block --bucket <bucket>
  # check all four booleans == true in both outputs
  ```
- **Remediation:** `aws s3control put-public-access-block --account-id <id> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`, and the equivalent `aws s3api put-public-access-block` per bucket for any exceptions.

### 4.8 — Ensure S3 object-level logging for write events is enabled
- **Level:** 2 | **Checks:** `cloudtrail_s3_dataevents_write_enabled`
- **Pass/Fail:** Pass if at least one CloudTrail trail has a data event selector (or advanced event selector) capturing `AWS::S3::Object` write events (`PutObject`, `DeleteObject`, etc.) for the buckets in scope. Fail if no trail logs S3 data-plane write events.
- **AWS CLI:**
  ```bash
  aws cloudtrail get-event-selectors --trail-name <trail>
  # classic selectors: DataResources[].Type == "AWS::S3::Object" and ReadWriteType in ("All","WriteOnly")
  # advanced selectors: AdvancedEventSelectors[] with a field "eventCategory"="Data" and resources.type S3
  ```
- **Remediation:** `aws cloudtrail put-event-selectors --trail-name <trail> --event-selectors '[{"ReadWriteType":"WriteOnly","IncludeManagementEvents":true,"DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3:::"]}]}]'` (or the equivalent advanced-event-selector JSON).

### 4.9 — Ensure S3 object-level logging for read events is enabled
- **Level:** 2 | **Checks:** `cloudtrail_s3_dataevents_read_enabled`
- **Pass/Fail:** Same mechanism as 4.8, but for read events (`GetObject`). Pass if a trail captures `ReadWriteType` `All` or `ReadOnly` for S3 data events; fail otherwise.
- **AWS CLI:** Same as 4.8 — `aws cloudtrail get-event-selectors --trail-name <trail>`, checking for `ReadOnly`/`All` coverage of S3 object data events.
- **Remediation:** Same call pattern as 4.8, using `ReadWriteType: "ReadOnly"` or `"All"`.

*(Server-side default encryption isn't a separate control in v7.0.0 — AWS enabled SSE-S3 by default for all buckets account-wide in January 2023, so CIS retired the "ensure encryption is enabled" S3 check that existed in older versions. If the skill wants to verify anyway, `aws s3api get-bucket-encryption --bucket <bucket>` still returns the effective config.)*

---

## 4. CloudTrail / logging

### 4.1 — Ensure CloudTrail is enabled in all regions
- **Level:** 1 | **Checks:** `cloudtrail_multi_region_enabled`
- **Pass/Fail:** Pass if at least one trail exists with `IsMultiRegionTrail=true` and that trail is actively logging (`IsLogging=true` from `get-trail-status`). Fail if no multi-region trail exists, or the only multi-region trail(s) present are stopped.
- **AWS CLI:**
  ```bash
  aws cloudtrail describe-trails --query 'trailList[?IsMultiRegionTrail==`true`]'
  aws cloudtrail get-trail-status --name <trail-arn>
  # check: IsLogging == true
  ```
- **Remediation:** `aws cloudtrail create-trail --name <name> --s3-bucket-name <bucket> --is-multi-region-trail`, then `aws cloudtrail start-logging --name <name>`.

### 4.2 — Ensure CloudTrail log file validation is enabled
- **Level:** 2 | **Checks:** `cloudtrail_log_file_validation_enabled`
- **Pass/Fail:** Pass if `LogFileValidationEnabled` is `true` on the trail, meaning CloudTrail writes signed digest files that can prove log integrity. Fail if not set.
- **AWS CLI:**
  ```bash
  aws cloudtrail describe-trails --query 'trailList[].{Name:Name,Validation:LogFileValidationEnabled}'
  ```
- **Remediation:** `aws cloudtrail update-trail --name <trail> --enable-log-file-validation`.

### 4.4 — Ensure server access logging is enabled on the CloudTrail S3 bucket
- **Level:** 1 | **Checks:** `cloudtrail_logs_s3_bucket_access_logging_enabled`
- **Pass/Fail:** Pass if the S3 bucket that CloudTrail delivers logs to itself has S3 server access logging turned on (to a separate target bucket). Fail if it doesn't — this closes the gap of who's reading/tampering with your audit trail's own storage.
- **AWS CLI:**
  ```bash
  aws cloudtrail describe-trails --query 'trailList[].S3BucketName'
  aws s3api get-bucket-logging --bucket <cloudtrail-bucket>
  # check: LoggingEnabled key is present with a TargetBucket
  ```
- **Remediation:** `aws s3api put-bucket-logging --bucket <cloudtrail-bucket> --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"<log-target-bucket>","TargetPrefix":"cloudtrail-access-logs/"}}'`.

### 4.5 — Ensure CloudTrail logs are encrypted at rest using KMS CMKs
- **Level:** 2 | **Checks:** `cloudtrail_kms_encryption_enabled`
- **Pass/Fail:** Pass if the trail has a non-null `KmsKeyId`, meaning log files are encrypted with a customer-managed KMS key (SSE-KMS) rather than only SSE-S3. Fail if `KmsKeyId` is absent.
- **AWS CLI:**
  ```bash
  aws cloudtrail describe-trails --query 'trailList[].{Name:Name,KmsKeyId:KmsKeyId}'
  ```
- **Remediation:** `aws cloudtrail update-trail --name <trail> --kms-key-id <kms-key-arn>` (the CMK's key policy must also grant CloudTrail the necessary encrypt/decrypt permissions).

### 4.7 — Ensure VPC flow logging is enabled in all VPCs
- **Level:** 2 | **Checks:** `vpc_flow_logs_enabled`
- **Pass/Fail:** Pass if every VPC in the account/region has at least one active flow log (ideally capturing `REJECT`, or `ALL`, traffic). Fail if any VPC has no flow log configured.
- **AWS CLI:**
  ```bash
  aws ec2 describe-vpcs --query 'Vpcs[].VpcId'
  aws ec2 describe-flow-logs --filter Name=resource-id,Values=<vpc-id>
  # cross-reference every VpcId against the ResourceId values returned by describe-flow-logs
  ```
- **Remediation:** `aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name <log-group> --deliver-logs-permission-arn <iam-role-arn>` (or deliver to S3 with `--log-destination-type s3`).

### 5.5 — Ensure CloudTrail configuration changes are monitored **[bonus/monitoring]**
- **Level:** 1 | **Checks:** `cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled`
- **Pass/Fail:** Pass if a metric filter on the CloudTrail-fed log group catches `CreateTrail`, `UpdateTrail`, `DeleteTrail`, `StartLogging`, `StopLogging` events, backed by an alarm with a working SNS subscription. Fail if any piece is missing.
- **AWS CLI:**
  ```bash
  aws logs describe-metric-filters --log-group-name <cloudtrail-log-group>
  aws cloudwatch describe-alarms --query "MetricAlarms[?MetricName=='<metric-name>']"
  aws sns list-subscriptions-by-topic --topic-arn <topic-arn>
  ```
- **Remediation:** Create a metric filter matching those five CloudTrail API event names, wire it to a CloudWatch alarm, and confirm at least one SNS subscription is in `Confirmed` state.

---

## 5. Security Groups / VPC network exposure

### 6.2 — Ensure no Network ACL allows ingress from 0.0.0.0/0 to admin ports
- **Level:** 1 | **Checks:** `ec2_networkacl_allow_ingress_any_port`, `ec2_networkacl_allow_ingress_tcp_port_22`, `ec2_networkacl_allow_ingress_tcp_port_3389`
- **Pass/Fail:** Pass if no NACL entry allows (`RuleAction=allow`) inbound traffic from `0.0.0.0/0` on TCP/UDP/ALL protocols covering port 22 (SSH) or 3389 (RDP). Fail if such a rule exists and isn't overridden by an earlier, more restrictive DENY rule (NACLs are evaluated in rule-number order).
- **AWS CLI:**
  ```bash
  aws ec2 describe-network-acls --query 'NetworkAcls[].Entries'
  # for each entry: Egress=false, RuleAction=allow, CidrBlock=0.0.0.0/0,
  # and (Protocol=="-1" or PortRange covers 22/3389) => flag, respecting rule number ordering vs any Deny
  ```
- **Remediation:** Edit the offending NACL rule to restrict the CIDR to known trusted ranges (or remove it, since NACLs are typically left permissive and security groups do the real filtering).

### 6.3 — Ensure no security group allows ingress from 0.0.0.0/0 to admin ports
- **Level:** 1 | **Checks:** `ec2_securitygroup_allow_ingress_from_internet_to_all_ports`, `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22`, `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389`
- **Pass/Fail:** Pass if no security group has an inbound rule with `IpRanges` containing `0.0.0.0/0` on port 22, 3389, or `-1` (all ports/protocols). Fail if any such rule exists, regardless of whether the security group is currently attached to a running resource.
- **AWS CLI:**
  ```bash
  aws ec2 describe-security-groups \
    --query "SecurityGroups[].{GroupId:GroupId,IpPermissions:IpPermissions}"
  # for each IpPermission: IpRanges[].CidrIp == "0.0.0.0/0" AND
  # (FromPort<=22<=ToPort or FromPort<=3389<=ToPort or IpProtocol=="-1")
  ```
- **Remediation:** Remove or narrow the offending rule with `aws ec2 revoke-security-group-ingress`, replacing `0.0.0.0/0` with specific known-good IPs/CIDRs, or route admin access through a bastion/SSM Session Manager instead.

### 6.4 — Ensure no security group allows ingress from ::/0 to admin ports
- **Level:** 1 | **Checks:** same as 6.3 (IPv6 variant)
- **Pass/Fail:** Same logic as 6.3 but checking `Ipv6Ranges[].CidrIpv6 == "::/0"` instead of the IPv4 wildcard — easy to miss since many audits only check IPv4.
- **AWS CLI:**
  ```bash
  aws ec2 describe-security-groups \
    --query "SecurityGroups[].{GroupId:GroupId,IpPermissions:IpPermissions}"
  # check IpPermissions[].Ipv6Ranges[].CidrIpv6 == "::/0" against ports 22/3389 or ALL
  ```
- **Remediation:** Same as 6.3, via `aws ec2 revoke-security-group-ingress --ip-permissions` targeting the IPv6 range entry.

### 6.5 — Ensure the default security group of every VPC restricts all traffic
- **Level:** 2 | **Checks:** `ec2_securitygroup_default_restrict_traffic`
- **Pass/Fail:** Pass if every VPC's `default` security group has zero inbound rules and zero outbound rules (fully locked down, forcing all resources into explicitly-created groups). Fail if the default group still has any rule, including its factory-default "allow all traffic between members of this group."
- **AWS CLI:**
  ```bash
  aws ec2 describe-security-groups --filters Name=group-name,Values=default \
    --query 'SecurityGroups[].{GroupId:GroupId,VpcId:VpcId,In:IpPermissions,Out:IpPermissionsEgress}'
  # pass only if both IpPermissions and IpPermissionsEgress are empty arrays
  ```
- **Remediation:** Move any resources still using the default security group into purpose-built groups, then strip all ingress/egress rules from the default group with `aws ec2 revoke-security-group-ingress` / `revoke-security-group-egress`.

### 6.6 — Ensure VPC peering route tables are "least access"
- **Level:** 2 | **Checks:** `vpc_peering_routing_tables_with_least_privilege`
- **Pass/Fail:** Pass if routes pointing at a `VpcPeeringConnectionId` target only the specific subnets/hosts actually needed on the other side (a narrow `DestinationCidrBlock`). Fail if a peering route uses an overly broad CIDR (e.g., routing the entire peer VPC's CIDR when only one subnet needs reachability) — largely a judgment call, hard to fully automate.
- **AWS CLI:**
  ```bash
  aws ec2 describe-vpc-peering-connections
  aws ec2 describe-route-tables \
    --query "RouteTables[].Routes[?VpcPeeringConnectionId!=null]"
  # inspect DestinationCidrBlock breadth relative to the actual peer VPC CIDR and business need
  ```
- **Remediation:** Delete the overly broad route and add narrower routes limited to the specific subnets/hosts required via `aws ec2 delete-route` / `aws ec2 create-route`.

### 6.7 — Ensure the EC2 Metadata Service only allows IMDSv2
- **Level:** 1 | **Checks:** `ec2_instance_imdsv2_enabled`
- **Pass/Fail:** Pass if every running EC2 instance has `MetadataOptions.HttpTokens` set to `required` (IMDSv2 enforced, session-token based). Fail if `HttpTokens` is `optional` (IMDSv1 still reachable), since IMDSv1 is a common SSRF-to-credential-theft vector.
- **AWS CLI:**
  ```bash
  aws ec2 describe-instances \
    --query 'Reservations[].Instances[].{Id:InstanceId,Tokens:MetadataOptions.HttpTokens}'
  # flag anywhere Tokens != "required"
  ```
- **Remediation:** `aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required --http-endpoint enabled`, and set `HttpTokens=required` in the launch template/AMI default for future instances.

### 6.8 — Ensure VPC Endpoints are used for access to AWS services *(new in v7.0.0, no automated Prowler check yet)*
- **Level:** 2 | **Checks:** *(none — currently manual-only)*
- **Pass/Fail:** Pass if traffic from workloads to commonly-used AWS services (S3, DynamoDB, Secrets Manager, etc.) stays on the AWS private network via Gateway or Interface VPC Endpoints rather than transiting an Internet Gateway/NAT Gateway. Fail if VPCs have no endpoints and route service traffic out to the public internet. This is inherently more architectural than the other network controls and harder to reduce to a single pass/fail signal.
- **AWS CLI:**
  ```bash
  aws ec2 describe-vpc-endpoints --query 'VpcEndpoints[].{Vpc:VpcId,Service:ServiceName,State:State}'
  aws ec2 describe-route-tables   # cross-check whether S3/DynamoDB traffic could otherwise only exit via a NAT/IGW route
  ```
- **Remediation:** `aws ec2 create-vpc-endpoint --vpc-id <vpc> --service-name com.amazonaws.<region>.s3 --route-table-ids <rtb> --vpc-endpoint-type Gateway` for S3/DynamoDB, or `--vpc-endpoint-type Interface` with a subnet/security-group for other services (Secrets Manager, KMS, SSM, etc.).

### 5.10 — Ensure security group changes are monitored **[bonus/monitoring]**
- **Level:** 2 | **Checks:** `cloudwatch_log_metric_filter_security_group_changes`
- **Pass/Fail:** Pass if a metric filter on the CloudTrail log group catches `AuthorizeSecurityGroupIngress`, `AuthorizeSecurityGroupEgress`, `RevokeSecurityGroupIngress`, `RevokeSecurityGroupEgress`, `CreateSecurityGroup`, `DeleteSecurityGroup`, backed by a working alarm+subscription. Fail if any piece is missing.
- **AWS CLI:**
  ```bash
  aws logs describe-metric-filters --log-group-name <cloudtrail-log-group>
  aws cloudwatch describe-alarms --query "MetricAlarms[?MetricName=='<metric-name>']"
  aws sns list-subscriptions-by-topic --topic-arn <topic-arn>
  ```
- **Remediation:** Create the metric filter for those six SG-related API calls, attach a CloudWatch alarm, and verify a confirmed SNS subscription exists.

---

## 6. Root account settings/protections

### 2.2 — Maintain current AWS account contact details
- **Level:** 1 | **Checks:** `account_maintain_current_contact_details`
- **Pass/Fail:** Manual control — pass if the account's primary contact email/phone are current and (ideally) map to a distribution list/team rather than one individual, so AWS can reach someone during a suspected compromise. There's no fully reliable automated way to verify "correctness," only that the fields are populated.
- **AWS CLI:**
  ```bash
  aws account get-contact-information
  # returns FullName, PhoneNumber, AddressLine1, etc. — check completeness/freshness only, correctness needs a human
  ```
- **Remediation:** Update via Billing Console → Account settings, or `aws account put-contact-information`, ideally pointing at a team alias/hunt group rather than a single person.

### 2.3 — Ensure security contact information is registered
- **Level:** 1 | **Checks:** `account_security_contact_information_is_registered`
- **Pass/Fail:** Pass if the account has a Security alternate contact configured (name, email, phone). Fail if the Security alternate contact fields are empty — AWS uses this to route security-relevant notices (e.g., abuse reports) to the right team instead of the account owner alone.
- **AWS CLI:**
  ```bash
  aws account get-alternate-contact --alternate-contact-type SECURITY
  # a "ResourceNotFoundException" means it's not set => fail
  ```
- **Remediation:** `aws account put-alternate-contact --alternate-contact-type SECURITY --email-address <alias> --name "<team>" --phone-number "<number>" --title "Security Team"`.

### 2.4 — Ensure no root user access key exists
- **Level:** 1 | **Checks:** `iam_no_root_access_key`
- **Pass/Fail:** Pass if the root account has zero active access keys. Fail if any root access key exists (active or inactive) — root should only ever use console sign-in with MFA, never programmatic API keys.
- **AWS CLI:**
  ```bash
  aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'
  # 0 = none exist (pass), 1 = at least one exists (fail)
  ```
- **Remediation:** Sign in as root → IAM console → My Security Credentials → Access keys → Delete, for every listed key.

### 2.7 — Eliminate use of the root user for administrative and daily tasks
- **Level:** 1 | **Checks:** `iam_avoid_root_usage`
- **Pass/Fail:** Pass if root shows no sign-in or API activity in the recent audit window (typically last 1–7 days, ideally never outside a documented break-glass event). Fail if root's `password_last_used` or any root access-key `last_used` timestamp is recent — every root action should really be traceable to a documented, exceptional reason.
- **AWS CLI:**
  ```bash
  aws iam generate-credential-report
  aws iam get-credential-report --query Content --output text | base64 -d > credreport.csv
  # inspect the root row: password_last_used, access_key_1_last_used_date, access_key_2_last_used_date
  # (cross-reference against CloudTrail for full fidelity, since credential report only has last-used, not full history)
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=root
  ```
- **Remediation:** Create named IAM users/roles (with appropriate permissions and MFA) for every admin who currently uses root for day-to-day work; reserve root strictly for the small set of tasks that genuinely require it (e.g., closing the account, some billing changes).

### 5.3 — Ensure usage of the root account is monitored **[bonus/monitoring]**
- **Level:** 1 | **Checks:** `cloudwatch_log_metric_filter_root_usage`
- **Pass/Fail:** Pass if a metric filter on the CloudTrail log group triggers on any event where `userIdentity.type = "Root"` (and it isn't the automated AWS service event), backed by an alarm with a confirmed SNS subscription. Fail if any piece is missing — this is the real-time detective control that complements 2.7's point-in-time check.
- **AWS CLI:**
  ```bash
  aws logs describe-metric-filters --log-group-name <cloudtrail-log-group>
  aws cloudwatch describe-alarms --query "MetricAlarms[?MetricName=='<metric-name>']"
  aws sns list-subscriptions-by-topic --topic-arn <topic-arn>
  ```
- **Remediation:** Create a metric filter matching root-identity CloudTrail events (excluding AWS-service-linked activity), attach a CloudWatch alarm, and verify an active SNS subscription so the team is paged the moment root is used.

**Root's MFA controls (2.5 hardware/virtual, 2.6 hardware-required) are covered in full under Section 2 (MFA) above — not repeated here to avoid duplication.**

---

## Notes for implementing the skill's evaluation logic

1. **Credential report is your single richest source for section 1/2 (IAM+MFA).** `aws iam generate-credential-report` + `aws iam get-credential-report` in one CSV gives you password age, MFA status, and both access keys' age/rotation/last-use for every user, including root (as a synthetic `<root_account>` row) — pull it once per audit run rather than issuing dozens of `list-*`/`get-*` calls per user.
2. **The monitoring `[bonus]` controls (5.2, 5.3, 5.5, 5.10) need three API calls chained together** (metric filter → alarm → SNS subscription) and are the only controls in this set where "the resource exists" isn't enough — the SNS subscription must also be in `Confirmed` state, or the alarm is silently useless.
3. **Multi-region checks (4.1 CloudTrail, 6.2–6.7 SG/NACL/IMDSv2) must be run once per enabled region**, not just the audit's home region — a single global `describe-security-groups` call only returns the caller's configured region.
4. **`s3control get-public-access-block`/`put-public-access-block` are account-level** (no `--bucket` flag) while `s3api get-public-access-block`/`put-public-access-block` are bucket-level — easy to mix up, and 3.1.4 requires checking both.
5. **IAM policy documents from `get-policy-version` are URL-encoded JSON** unless you pass `--query Document` through, and multi-statement policies need every `Statement` entry checked, not just the first, for controls like 2.14 and 2.21.

---

## Sources

- [CIS Benchmarks April 2026 Update](https://www.cisecurity.org/insights/blog/cis-benchmarks-april-2026-update) — confirms CIS AWS Foundations Benchmark v7.0.0 as the current release (announced April 2026).
- [CIS Amazon Web Services Foundations Benchmark v5.0.0 (03-31-2025 PDF)](https://itsecure.hu/wp-content/uploads/2025/05/CIS_Amazon_Web_Services_Foundations_Benchmark_v5.0.0.pdf) — prior stable version, used for the v5.0.0 cross-reference numbering.
- [AWS Security Hub CSPM now supports CIS AWS Foundations Benchmark v5.0](https://aws.amazon.com/about-aws/whats-new/2025/10/aws-security-hub-cspm-cis-foundations-benchmark-v5/) — evidence of AWS-native tooling's version lag behind CIS's own releases.
- [CIS Amazon Web Services Foundations Benchmark v7.0.0 compliance definition (Prowler Hub)](https://hub.prowler.com/compliance/cis_7.0_aws) — human-readable compliance framework page.
- [Prowler `cis_7.0_aws.json` compliance mapping (GitHub, prowler-cloud/prowler)](https://github.com/prowler-cloud/prowler/blob/master/prowler/compliance/aws/cis_7.0_aws.json) — primary source for exact control IDs, titles, levels, descriptions, rationale, and remediation text used throughout this document.
- [Prowler `cis_5.0_aws.json` compliance mapping (GitHub, prowler-cloud/prowler)](https://github.com/prowler-cloud/prowler/blob/master/prowler/compliance/aws/cis_5.0_aws.json) — source for the v5.0.0 cross-reference IDs.
- [CIS Amazon Web Services Foundations Benchmark v6.0.0 (Scribd)](https://www.scribd.com/document/963047399/CIS-Amazon-Web-Services-Foundations-Benchmark-v6-0-0) — intermediate version, confirmed superseded by v7.0.0.
- [CIS AWS Foundations Benchmark in Security Hub CSPM (AWS docs)](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.md) — background on how AWS surfaces CIS findings natively.
- AWS CLI command syntax verified against general AWS CLI v2 API knowledge (`iam`, `s3api`, `s3control`, `cloudtrail`, `ec2`, `logs`, `cloudwatch`, `sns`, `account` command groups).
