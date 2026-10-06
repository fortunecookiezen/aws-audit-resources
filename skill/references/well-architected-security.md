# AWS Well-Architected Framework — Security Pillar Mapping
### Reference doc for AWS account security audit skill (scoped: IAM, MFA, S3, CloudTrail/Logging, Security Groups/VPC, Root Account)

This doc maps each of the six audit areas to the current AWS Well-Architected Framework **Security Pillar** best-practice questions (SEC01–SEC10) and their individual best practices (`SECxx-BPyy`). It is meant to sit alongside CIS AWS Foundations Benchmark controls — the technical checks are the same; this adds the official AWS *why* (risk rationale, desired outcome) on top of each check.

Best-practice text below is condensed/paraphrased from the AWS Well-Architected Framework Security Pillar docs (`docs.aws.amazon.com/wellarchitected`), current as of August 2026. Where a BP page covers more ground than the six audit areas, only the portion relevant to a concrete, checkable configuration is included.

---

## 1. IAM (users, policies, password policy, access keys, root usage)

Primary Security Pillar question: **SEC02 — How do you manage authentication for people and machines?** and **SEC03 — How do you manage permissions for people and machines?**

### SEC02-BP01 — Use strong sign-in mechanisms (password-policy portion)
- **Plain-language description:** Sign-ins should require strong passwords and MFA. For IAM users specifically, set an account password policy (minimum length, complexity, reuse prevention, expiration) via `SetAccountPasswordPolicy`, and prefer centralizing identities instead of many standalone IAM user passwords.
- **Pass:** Account-level IAM password policy is set and enforces at minimum: length ≥ 14, requires uppercase/lowercase/number/symbol, prevents reuse of recent passwords, and expires passwords (with account exempt only for identities that require it).
- **Fail:** No custom password policy set (AWS default is weak/absent), or policy allows short/simple passwords with no expiration or reuse protection.
- **Remediation:** Set an IAM account password policy meeting organizational/NIST 800-63-aligned requirements; migrate human users to federated access via IAM Identity Center where possible so password policy is centrally enforced.

### SEC02-BP02 — Use temporary credentials
- **Plain-language description:** Prefer IAM roles and temporary, auto-expiring credentials (STS) over long-lived IAM user access keys for both human and machine access.
- **Pass:** Human users and workloads primarily assume roles for access; long-term IAM user access keys exist only where unavoidable and are tracked/justified.
- **Fail:** Widespread use of long-lived IAM user access keys embedded in code/config/CI systems for access that could use a role.
- **Remediation:** Replace static access keys with IAM roles (EC2 instance profiles, Lambda execution roles, IAM Roles Anywhere for on-prem) and federated/SSO access for people.

### SEC02-BP05 — Audit and rotate credentials periodically
- **Plain-language description:** Long-term credentials (IAM user access keys, passwords) must be periodically audited and rotated because a leaked long-lived credential stays exploitable indefinitely otherwise. AWS's stated maximum rotation cadence for access keys is **90 days**.
- **Pass:** All active IAM user access keys are ≤ 90 days old (or rotated on a defined cadence); IAM credential report is reviewed regularly; unused credentials/users are identified and removed.
- **Fail:** Access keys older than 90 days in active use; no periodic credential audit process; stale/unused IAM users or keys (e.g., no activity in 90+ days) still enabled.
- **Remediation:** Enforce key rotation ≤ 90 days (automate via Config rule + Lambda or IAM Access Analyzer unused-access findings), and disable/delete IAM users, roles, and keys with no recent activity.

### SEC02-BP06 — Employ user groups and attributes
- **Plain-language description:** Manage IAM permissions through groups (or roles/ABAC tags) rather than attaching policies directly to individual IAM users, to keep permissions consistent and auditable.
- **Pass:** No IAM user has a policy attached directly to it; all human-user permissions flow through groups or federated roles.
- **Fail:** One or more IAM users have inline or directly-attached managed policies.
- **Remediation:** Move directly-attached policies to a group (or role), attach the group to the user, and detach the direct policy.

### SEC03-BP02 — Grant least privilege access
- **Plain-language description:** IAM policies (for users, groups, and roles) should grant only the permissions needed to perform a task, using customer-managed policies scoped to specific actions/resources rather than broad AWS-managed policies or wildcard permissions.
- **Pass:** No IAM policy grants `"Action": "*"` with `"Resource": "*"` (full admin) to non-break-glass principals; sensitive/administrative policies are scoped and justified.
- **Fail:** IAM users, groups, or roles have policies granting `*:*` or otherwise broad, unscoped administrative access without justification.
- **Remediation:** Replace wildcard policies with least-privilege, customer-managed policies; use IAM Access Analyzer policy generation and unused-access findings to right-size permissions.

### SEC03-BP04 — Reduce permissions continuously
- **Plain-language description:** Permissions granted tend to accumulate and go unused over time; they should be reviewed and trimmed on an ongoing basis rather than only granted once.
- **Pass:** A recurring process (manual or automated via IAM Access Analyzer) reviews and removes unused permissions/roles/users.
- **Fail:** No evidence of periodic permission review; long-unused IAM entities and permissions remain in place indefinitely.
- **Remediation:** Enable IAM Access Analyzer's unused-access findings and schedule periodic access reviews; remove permissions and entities with no recent usage.

> **Root account usage** is also an IAM identity concern, but AWS Well-Architected treats it as its own topic (SEC01-BP02) — see **Section 6: Root Account Protections** below for the full mapping.

---

## 2. MFA (root and IAM users)

Primary Security Pillar question: **SEC01 — How do you securely operate your workload?** (root) and **SEC02 — How do you manage authentication for people and machines?** (IAM users)

### SEC01-BP02 — Secure account root user and properties (MFA portion)
- **Plain-language description:** The root user must have MFA enabled — ideally a hardware MFA device for resilience — because root is the single most privileged, unrestrictable identity in the account.
- **Pass:** MFA is enabled and active on the root user (`account:summary` shows `MFADevices=1`); for AWS Organizations management accounts, a hardware MFA device is used.
- **Fail:** Root user has no MFA device configured.
- **Remediation:** Enable MFA on the root user immediately (virtual or, preferably, hardware MFA device); enroll a backup device where supported.

### SEC02-BP01 — Use strong sign-in mechanisms (MFA portion, IAM users)
- **Plain-language description:** All human IAM identities should be required to use MFA at sign-in, not just recommended to — enforced via an IAM policy that denies actions unless MFA is present, or via IAM Identity Center MFA settings for federated users.
- **Pass:** Every IAM user with console access has an MFA device attached (or console access is deprecated in favor of federated SSO with MFA enforced centrally); an IAM policy denies unauthenticated (non-MFA) API access to sensitive actions.
- **Fail:** One or more IAM users with console access/login profiles have no MFA device attached.
- **Remediation:** Require MFA enrollment for every IAM user with console access (enforce via IAM policy condition `aws:MultiFactorAuthPresent`), and move toward centralized identity (IAM Identity Center) with MFA enforced at the source.

---

## 3. S3 Bucket Security (public access, encryption, logging)

Primary Security Pillar question: **SEC03 — How do you manage permissions for people and machines?**, **SEC08 — How do you protect your data at rest?**, and **SEC04 — How do you detect and investigate security events?** (for access logging)

### SEC03-BP07 — Analyze public and cross-account access
- **Plain-language description:** Continuously know which resources (notably S3 buckets) are shared publicly or cross-account, and reduce that exposure to only what's explicitly required. AWS calls out S3 Block Public Access specifically as a control to enable and monitor.
- **Pass:** S3 Block Public Access is enabled at the account level (and per-bucket); IAM Access Analyzer / AWS Config / Trusted Advisor report no buckets with unintended public or cross-account access; any legitimate public/cross-account bucket is explicitly documented and approved.
- **Fail:** Account-level S3 Block Public Access is not enabled; one or more buckets have public ACLs, public bucket policies, or unreviewed cross-account access.
- **Remediation:** Turn on S3 Block Public Access at the account level and on each bucket; use AWS Config auto-remediation and IAM Access Analyzer to detect and alert on any drift back to public/cross-account exposure.

### SEC08-BP04 — Enforce access control (S3 portion)
- **Plain-language description:** Beyond blocking public access, actively review bucket policies/ACLs for over-broad grants, apply least privilege to who can read/write data, and use versioning to protect against accidental or malicious modification/deletion.
- **Pass:** Bucket policies and ACLs grant access only to specific, justified principals (no `Principal: "*"` without a compensating condition); versioning is enabled on buckets holding important data.
- **Fail:** A bucket policy or ACL grants read/write/list to "Everyone"/"Any authenticated AWS user" without justification; no versioning on data buckets that need it.
- **Remediation:** Rewrite bucket policies to name specific principals/conditions, remove public/broad ACL grants, and enable S3 Versioning (with MFA delete or Object Lock for critical data).

### SEC08-BP02 — Enforce encryption at rest (S3 portion)
- **Plain-language description:** Data in S3 should be encrypted by default so that unintended disclosure (e.g., through misconfiguration or exfiltration) doesn't expose plaintext data. Modern S3 encrypts new objects by default (SSE-S3), but a check should confirm default encryption / a bucket-level enforcement is actually in place, ideally with KMS for sensitive data.
- **Pass:** Every bucket has default encryption configured (SSE-S3 or SSE-KMS); a bucket policy denies unencrypted (`PutObject` without `x-amz-server-side-encryption`) uploads for buckets holding sensitive data.
- **Fail:** A bucket has no default encryption configured and/or accepts unencrypted object uploads.
- **Remediation:** Enable default bucket encryption (SSE-S3 at minimum, SSE-KMS with a customer-managed key for sensitive data) and add a bucket policy condition denying uploads that don't specify server-side encryption.

### SEC04-BP01 — Configure service and application logging (S3 access-logging portion)
- **Plain-language description:** S3 buckets should have access logging enabled (server access logs or CloudTrail data events) so that object-level reads/writes are recorded for investigation, in line with the broader logging best practice.
- **Pass:** S3 server access logging (or CloudTrail S3 data-event logging) is enabled on buckets holding sensitive/important data, with logs delivered to a separate, access-controlled bucket.
- **Fail:** No access logging configured on sensitive buckets; logs (if any) are stored in the same bucket they log, or are not access-restricted.
- **Remediation:** Enable S3 server access logging (or CloudTrail data events for S3) and deliver logs to a dedicated, locked-down logging bucket with lifecycle retention.

---

## 4. CloudTrail / Logging & Monitoring

Primary Security Pillar question: **SEC04 — How do you detect and investigate security events?**

### SEC04-BP01 — Configure service and application logging (CloudTrail portion)
- **Plain-language description:** Establish an AWS CloudTrail trail (ideally an AWS Organizations trail) covering all regions, capturing management events at minimum, and delivering logs to a durable, access-controlled destination (S3 and/or CloudWatch Logs) with an appropriate retention period. CloudTrail is on by default with only 90 days of management-event history via Event History — a durable trail is required for real retention and completeness.
- **Pass:** A CloudTrail trail exists that is multi-region ("all regions"), logs both management and (where relevant) data events, delivers to a dedicated S3 bucket (and/or CloudWatch Logs group), has log file integrity validation enabled, and retention meets policy (commonly 1+ year, up to 7 years via CloudTrail Lake).
- **Fail:** No CloudTrail trail configured beyond the default 90-day Event History; trail is single-region only; log file validation disabled; trail delivers to a bucket with no lifecycle/retention policy or with public/broad access.
- **Remediation:** Create (or verify) a CloudTrail trail with "Apply trail to all regions" enabled, log file validation on, delivery to a dedicated encrypted S3 bucket (with restrictive bucket policy) and/or CloudWatch Logs, and a retention policy matching compliance requirements.

### SEC04-BP02 — Capture/analyze logs, findings, and metrics in standardized (centralized) locations
- **Plain-language description:** Logs and findings (CloudTrail, Config, GuardDuty, VPC Flow Logs, etc.) should be aggregated to a small number of standardized, centrally-monitored locations — not scattered per-account/per-service — with alerting on key security-relevant events (e.g., root usage, IAM policy changes, unauthorized API calls).
- **Pass:** Logs are centralized (e.g., a log-archive/security-tooling account or SIEM); CloudWatch alarms/EventBridge rules or GuardDuty/Security Hub are active and alert on sensitive events such as root login, IAM policy changes, and unauthorized API calls (aligned with CIS's CloudWatch alarm controls).
- **Fail:** Logs remain siloed per account/region with no central visibility; no alarms/findings configured for sensitive API activity.
- **Remediation:** Route CloudTrail/Config/VPC Flow Logs to a centralized log-archive destination (or Security Lake), and configure CloudWatch alarms / EventBridge rules / GuardDuty findings for root usage and other high-risk events.

---

## 5. Security Groups / VPC Network Exposure

Primary Security Pillar question: **SEC05 — How do you protect your network resources?**

### SEC05-BP01 — Create network layers
- **Plain-language description:** Group resources by sensitivity into network layers/subnets (e.g., public, application, data tiers) so that a compromise in one layer doesn't directly expose another — databases, for example, should never sit in a subnet/security-group configuration reachable directly from the internet. AWS explicitly calls out "using overly permissive security groups" as a common anti-pattern here.
- **Pass:** Sensitive resources (databases, internal services) are in private subnets with security groups that only allow traffic from the specific adjacent-layer security group (not from the internet or an entire VPC CIDR).
- **Fail:** Databases or internal-only resources are placed in public subnets or have security groups allowing broad/internet-facing ingress.
- **Remediation:** Redesign network layering so sensitive resources sit in private subnets, and scope security group rules to reference specific source security groups rather than open CIDR ranges.

### SEC05-BP02 — Control traffic at all layers (security groups & NACLs)
- **Plain-language description:** Apply defense-in-depth for inbound/outbound traffic using security groups (stateful, instance-level firewall) together with network ACLs (stateless, subnet-level). Security group rules should reference other security groups where possible rather than open CIDR blocks, and resources shouldn't be directly internet-reachable without a load balancer/CloudFront in front of them.
- **Pass:** No security group allows inbound traffic on sensitive/management ports (22, 3389, database ports like 3306/5432/1433/27017, etc.) from `0.0.0.0/0` or `::/0`; internet-facing compute sits behind a load balancer/CloudFront rather than being directly reachable; NACLs provide a secondary layer of restriction where used.
- **Fail:** Any security group has an inbound rule with source `0.0.0.0/0` (or `::/0`) opening SSH/RDP or a database/admin port directly to the internet.
- **Remediation:** Remove/replace open-CIDR ingress rules on sensitive ports with specific IP ranges (e.g., corporate VPN/bastion CIDR) or reference a specific source security group; require use of a bastion/Session Manager/VPN and a load balancer for any internet-facing access.

### SEC05-BP04 — Automate network protection
- **Plain-language description:** Use automated tooling (AWS Config rules, Firewall Manager, AWS WAF) to continuously detect and remediate network misconfigurations — like an overly permissive security group — rather than relying solely on point-in-time manual review.
- **Pass:** AWS Config rules (e.g., `restricted-ssh`, `restricted-common-ports`) or Firewall Manager security group policies are active and auto-remediate/flag violations.
- **Fail:** No automated detection of security-group drift; permissive rules can be introduced and persist undetected.
- **Remediation:** Enable relevant AWS Config managed rules for security groups and/or deploy AWS Firewall Manager security group policies across the organization.

---

## 6. Root Account Protections

Primary Security Pillar question: **SEC01 — How do you securely operate your workload?**

### SEC01-BP02 — Secure account root user and properties
This is the single most directly relevant best practice for root-account auditing; it bundles several concrete, checkable sub-controls:

| Sub-control | Pass | Fail | Remediation |
|---|---|---|---|
| **Root MFA** | Root user has an MFA device (hardware MFA preferred, especially for AWS Organizations management accounts) enrolled and active. | No MFA device on root. | Enable MFA on root immediately; use a hardware token for the management account. |
| **No root access keys** | Root user has zero active access keys. | One or more access keys exist on the root user. | Delete all root access keys; migrate any process using them to an IAM role with temporary credentials. |
| **Root not used for routine tasks** | CloudTrail shows root sign-ins/API calls only for the narrow set of [tasks that require root](https://docs.aws.amazon.com/general/latest/gr/aws_tasks-that-require-root.html), rarely/never for daily operations. | Frequent root console logins or API activity for routine administrative work. | Create/use least-privilege IAM roles or IAM Identity Center for daily administration; reserve root strictly for account-recovery or root-only tasks. |
| **Root contact info & recovery hardened** | Root email is a monitored distribution list on the corporate domain; recovery phone is dedicated and secured; a documented two-person process governs root credential/MFA custody. | Root email is a single individual's personal/unmonitored inbox; no documented recovery/break-glass process. | Move root email to a monitored distribution list, secure the recovery phone, and document a two-person break-glass process. |
| **Root usage alerting** | CloudWatch alarm / EventBridge rule / GuardDuty (`RootCredentialUsage` finding) fires on any root sign-in or API activity. | No alerting configured for root usage. | Create a CloudWatch metric filter + alarm on CloudTrail root usage (or enable GuardDuty and alert on `RootCredentialUsage` findings). |
| **Preventive guardrails (multi-account)** | AWS Control Tower / SCP guardrails such as "Disallow Creation of Root Access Keys" and "Disallow Actions as a Root User" are enabled where AWS Organizations is in use. | No such guardrails deployed in a multi-account org. | Enable the relevant Control Tower strongly-recommended controls or equivalent SCPs across the organization. |

- **Level of risk if not established (per AWS):** High.
- **Overall remediation summary:** Enable MFA (hardware where possible) on root, remove all root access keys, restrict root use to the narrow set of root-only tasks, secure root's recovery contact info under a two-person process, and alert on any root usage via CloudWatch/GuardDuty.

---

## Sources

- [Security - AWS Well-Architected Framework (overview)](https://docs.aws.amazon.com/wellarchitected/latest/framework/security.html)
- [Security Pillar - AWS Well-Architected Framework (whitepaper landing page)](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [Security foundations - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/security.html)
- [Identity management - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/identity-management.html)
- [Permissions management - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/permissions-management.html)
- [Detection - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/detection.html)
- [Infrastructure protection - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/infrastructure-protection.html)
- [Protecting networks - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/protecting-networks.html)
- [Data protection - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/data-protection.html)
- [Protecting data at rest - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/protecting-data-at-rest.html)
- [SEC01-BP02 Secure account root user and properties](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_securely_operate_aws_account.html)
- [SEC02-BP01 Use strong sign-in mechanisms](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_identities_enforce_mechanisms.html)
- [SEC02-BP02 Use temporary credentials](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_identities_unique.html)
- [SEC02-BP05 Audit and rotate credentials periodically](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_identities_audit.html)
- [SEC03-BP07 Analyze public and cross-account access](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_permissions_analyze_cross_account.html)
- [SEC04-BP01 Configure service and application logging](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_detect_investigate_events_app_service_logging.html)
- [SEC04-BP02 Capture logs, findings, and metrics in standardized locations](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_detect_investigate_events_logs.html)
- [SEC05-BP01 Create network layers](https://docs.aws.amazon.com/wellarchitected/2023-04-10/framework/sec_network_protection_create_layers.html)
- [SEC05-BP02 Control traffic at all layers](https://docs.aws.amazon.com/wellarchitected/2023-04-10/framework/sec_network_protection_layered.html)
- [SEC05-BP04 Automate network protection](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_network_auto_protect.html)
- [SEC08-BP02 Enforce encryption at rest](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_protect_data_rest_encrypt.html)
- [SEC08-BP04 Enforce access control](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_protect_data_rest_access_control.html)
