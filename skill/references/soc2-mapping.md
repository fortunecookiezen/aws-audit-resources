# SOC 2 (AICPA TSC 2017, Security/Common Criteria) — AWS Technical Mapping

Practical mapping between ten AWS security audit areas and the SOC 2 Trust Services
Criteria (TSC) Common Criteria (CC) series. Scoped to the Security ("Common Criteria")
category only — not the full TSC (Availability, Confidentiality, Processing Integrity,
Privacy). Intended for use in an audit skill that reports findings like:

> "Public S3 bucket `X` with no encryption relates to SOC 2 criteria CC6.1, CC6.6, and CC6.7."

---

## 1. IAM (users, policies, password policy, access keys, root account usage)

**Criteria:** CC6.1, CC6.2, CC6.3

| ID | Title / summary |
|---|---|
| CC6.1 | Implement logical access security software, infrastructure, and architectures over protected information assets to protect them from security events. |
| CC6.2 | Register and authorize new internal and external users before issuing system credentials and granting system access; remove access when no longer required. |
| CC6.3 | Authorize, modify, or remove access to data, software, functions, and other protected assets based on roles, responsibilities, or the system design and changes to them, using the concept of least privilege. |

**Why it matters:** IAM is the system that *implements* CC6.1's "logical access security
architecture" in AWS. CC6.2 requires a defined process for provisioning credentials
(no ad hoc account creation, no shared logins), and CC6.3 requires access to be
tied to role and kept current — i.e., least privilege, no stale permissions, and a
real deprovisioning process. Weak password policies, long-lived unrotated access
keys, and overly broad IAM policies (`*:*` wildcards, unused admin policies) are the
concrete AWS symptoms of a CC6.2/CC6.3 control failure, and auditors specifically look
for evidence that access grants are individually justified and periodically reviewed.

**AWS evidence that would satisfy it:**
- IAM account password policy enforced (min length, complexity, expiration, reuse prevention) — `GetAccountPasswordPolicy`
- IAM Access Analyzer findings reviewed/resolved; no policies granting `*` on `*`
- Access keys rotated regularly (e.g., <90 days) and unused keys/credentials disabled — IAM credential report
- No use of the AWS root account for daily operations; IAM users/roles used instead
- Named individual IAM users or federated identities (SSO) — no shared/generic accounts
- Evidence of periodic access reviews (e.g., IAM Access Advisor "last used" data, quarterly recertification)
- Least-privilege policies scoped to specific resources/actions rather than managed `AdministratorAccess` attached broadly

---

## 2. MFA (root and IAM users)

**Criteria:** CC6.1, CC6.6

| ID | Title / summary |
|---|---|
| CC6.1 | Implement logical access security software, infrastructure, and architectures over protected information assets to protect them from security events (includes authentication mechanisms). |
| CC6.6 | Implement logical access security measures to protect against threats from sources outside the system boundaries. |

**Why it matters:** MFA is the canonical "logical access security measure" auditors
expect to see under CC6.1, and it is also the primary control for CC6.6 because
password-only authentication is the most common vector for external attackers
(credential stuffing, phishing, leaked credentials) to cross the account boundary.
An account with MFA disabled on the root user or on privileged IAM users is one of
the highest-severity findings in a SOC 2 readiness review because a single leaked
password becomes full account compromise.

**AWS evidence that would satisfy it:**
- Root account has a hardware or virtual MFA device attached — `GetAccountSummary` (`AccountMFAEnabled`)
- All (or all privileged) IAM users have MFA enabled — IAM credential report `mfa_active` column
- IAM policy/SCP conditionally denies API actions when `aws:MultiFactorAuthPresent` is false, for sensitive actions
- Console access requires MFA (enforced via IAM policy or IdP/SSO configuration)
- MFA delete enabled on critical S3 buckets (ties to Area 3 as well)

---

## 3. S3 Bucket Security (public access, encryption, logging)

**Criteria:** CC6.1, CC6.6, CC6.7

| ID | Title / summary |
|---|---|
| CC6.1 | Implement logical access security software, infrastructure, and architectures over protected information assets to protect them from security events (includes encryption of data at rest). |
| CC6.6 | Implement logical access security measures to protect against threats from sources outside the system boundaries (public/anonymous access to storage). |
| CC6.7 | Restrict and protect the transmission, movement, and removal of information to authorized internal and external users and processes, and protect it during transmission/removal. |

**Why it matters:** A publicly accessible or unencrypted S3 bucket is a direct
CC6.6 failure — it removes the system boundary entirely, letting anyone on the
internet reach protected data without authenticating. Missing encryption at rest
is a CC6.1 gap (no security architecture protecting the asset itself), and missing
encryption in transit (e.g., not enforcing TLS, no bucket policy denying non-HTTPS
requests) plus unrestricted object movement/exfiltration paths falls under CC6.7,
which governs how data is allowed to move and be removed from the environment.

**AWS evidence that would satisfy it:**
- S3 Block Public Access enabled at the account level and per-bucket
- No bucket ACLs or bucket policies granting `*`/`AllUsers`/`AuthenticatedUsers` access
- Default encryption enabled (SSE-S3 or SSE-KMS) on all buckets holding sensitive data
- Bucket policy denies `aws:SecureTransport: false` (enforces TLS in transit)
- S3 server access logging or CloudTrail S3 data events enabled for sensitive buckets
- Versioning and (for critical buckets) MFA Delete enabled to prevent unauthorized removal
- Cross-account/cross-region replication and lifecycle rules reviewed for unintended data movement

---

## 4. CloudTrail / Logging & Monitoring

**Criteria:** CC7.1, CC7.2, CC7.3 (supported by CC6.1 for log protection)

| ID | Title / summary |
|---|---|
| CC7.1 | Use detection and monitoring procedures to identify (1) changes to configurations that introduce new vulnerabilities and (2) susceptibilities to newly discovered vulnerabilities. |
| CC7.2 | Monitor system components and the operation of those components for anomalies indicative of malicious acts, natural disasters, and errors; analyze anomalies to determine whether they represent security events. |
| CC7.3 | Evaluate security events to determine whether they could or did result in a failure to meet objectives (security incidents) and, if so, take actions to prevent or address such failures. |

**Why it matters:** CC7.1–CC7.3 collectively require an organization to be able to
*see* what is happening in its environment, detect anomalies, and evaluate whether
they are real incidents. Without CloudTrail (or with it disabled, unencrypted, or
not centrally aggregated), there is no evidence trail to satisfy any of these
criteria — an auditor cannot verify detection capability if there is nothing being
logged. This is usually the single most load-bearing control area in an AWS SOC 2
audit because CloudTrail/Config/GuardDuty logs are the primary evidence source for
nearly every other CC7 and several CC6 control tests.

**AWS evidence that would satisfy it:**
- CloudTrail enabled in all regions, applied to the whole organization (multi-account) if applicable
- Trail is a multi-region trail with log file validation enabled (tamper-evidence)
- CloudTrail logs delivered to a dedicated, access-restricted, encrypted S3 bucket (and/or CloudWatch Logs) — supports CC6.1 (protecting the logs themselves)
- Log retention policy meeting the audit period (commonly ≥1 year)
- GuardDuty enabled for threat/anomaly detection (CC7.2)
- AWS Config enabled to detect configuration drift/changes (CC7.1)
- CloudWatch alarms/EventBridge rules on sensitive events (root login, IAM policy changes, security group changes, unauthorized API calls) with alerting to a monitored channel
- Documented process/evidence for triaging alerts (CC7.3) — e.g., Security Hub findings with an assigned owner and remediation status

---

## 5. Security Groups / VPC Network Exposure

**Criteria:** CC6.1, CC6.6

| ID | Title / summary |
|---|---|
| CC6.1 | Implement logical access security software, infrastructure, and architectures over protected information assets to protect them from security events (includes network segmentation/firewalling). |
| CC6.6 | Implement logical access security measures to protect against threats from sources outside the system boundaries. |

**Why it matters:** Security groups and VPC network ACLs are literally the "system
boundary" CC6.6 refers to in cloud terms — they are the perimeter control deciding
what traffic from the internet (or other VPCs/accounts) can reach a resource. A
security group open on `0.0.0.0/0` for SSH/RDP or a database port is a textbook
CC6.6 failure: it collapses the network boundary and lets anyone attempt access.
CC6.1 covers the broader network architecture — segmentation between tiers (public
subnets vs. private subnets vs. data stores), which limits blast radius even if one
layer is breached.

**AWS evidence that would satisfy it:**
- No security groups allow unrestricted inbound access (`0.0.0.0/0` or `::/0`) on sensitive ports (22, 3389, database ports, management ports)
- Security groups scoped to specific source CIDRs/security groups rather than "any"
- Databases and internal resources placed in private subnets with no direct internet route (no public IP / not behind an internet-facing load balancer)
- Network segmentation between public-facing and internal/data tiers (public vs. private subnets, separate route tables)
- VPC Flow Logs enabled (ties to Area 4 — supports CC7.2 detection as well)
- Bastion/SSM Session Manager used instead of broadly open SSH access
- Regular review process for unused/overly permissive security group rules

---

## 6. Root Account Protections

**Criteria:** CC6.1, CC6.2, CC6.3, CC6.6

| ID | Title / summary |
|---|---|
| CC6.1 | Implement logical access security software, infrastructure, and architectures over protected information assets to protect them from security events. |
| CC6.2 | Register and authorize new internal and external users before issuing system credentials and granting system access. |
| CC6.3 | Authorize, modify, or remove access based on roles/responsibilities using least privilege. |
| CC6.6 | Implement logical access security measures to protect against threats from sources outside the system boundaries. |

**Why it matters:** The AWS root user is the one identity that bypasses IAM policy
restrictions entirely and can never be fully constrained — so SOC 2 auditors treat
it as the highest-risk credential in the account. It is a direct violation of
least privilege (CC6.3) to use root for routine work, a CC6.2 gap if root
credentials aren't tightly controlled/registered to a specific accountable owner,
and a CC6.1/CC6.6 gap if it lacks strong authentication and is not monitored —
because a compromised root account is a complete, unrestrictable account takeover.

**AWS evidence that would satisfy it:**
- Root account MFA enabled (hardware token preferred) — overlaps with Area 2
- No access keys exist for the root user
- Root account not used for day-to-day operations — CloudTrail shows no/rare root logins, each with a documented business justification
- Root credentials (email, password) tightly controlled, with a documented owner and break-glass process
- Alerting configured (CloudWatch/EventBridge/GuardDuty) to notify on any root login or root API activity
- AWS account contact info (billing/security/operations) kept current for incident notification
- Organizations/SCPs used to further restrict what root can do at the member-account level, where applicable

---

## 7. Detection & Monitoring (GuardDuty, Security Hub, Inspector, Access Analyzer, AWS Config, log retention)

**Criteria:** CC7.1, CC7.2, CC7.3, CC8.1 (CC6.1/CC6.3 for Access Analyzer)

| ID | Title / summary |
|---|---|
| CC7.1 | Use detection and monitoring procedures to identify (1) changes to configurations that introduce new vulnerabilities and (2) susceptibilities to newly discovered vulnerabilities. |
| CC7.2 | Monitor system components and the operation of those components for anomalies indicative of malicious acts, natural disasters, and errors. |
| CC7.3 | Evaluate security events to determine whether they could or did result in a failure to meet objectives (security incidents). |
| CC8.1 | Authorize, design, develop or acquire, configure, document, test, approve, and implement changes to infrastructure, data, software, and procedures. |

**Why it matters:** Area 4 shows that activity is *logged*; this area shows that
someone or something is *watching* it. GuardDuty is the CC7.2 anomaly detector;
Security Hub aggregates findings so they can be triaged (CC7.3); Inspector is the
CC7.1 "susceptibilities to newly discovered vulnerabilities" control for EC2, ECR
images and Lambda; AWS Config is the CC7.1 configuration-change record and the
evidence base for CC8.1 change testing; IAM Access Analyzer surfaces resources
shared outside the account, a CC6.1/CC6.3 access-review input. Auditors test these
*per region*: a service enabled in the primary region but not in a region with
workloads (or one an attacker could use unseen) is a coverage gap. Log retention
shorter than the audit period means the evidence for the period no longer exists.

**AWS evidence that would satisfy it:**
- GuardDuty detector `ENABLED` in every enabled region, ideally org-wide from a delegated administrator — `guardduty_enabled`
- Security Hub enabled in every region with at least one standard (AWS FSBP or CIS) — `securityhub_enabled`
- Inspector scanning EC2, ECR and Lambda in every region — `inspector_enabled`
- An ACCOUNT or ORGANIZATION Access Analyzer active in every region, with findings reviewed — `access_analyzer_enabled`
- AWS Config recording all supported resource types in every region, global types in one — `config_recorder_enabled`
- CloudWatch log groups kept ≥ 365 days (or exported to S3 under a lifecycle policy that is) — `cloudwatch_log_group_retention`
- Evidence that findings from these services are triaged by a named owner (tickets, Security Hub workflow status) — manual

---

## 8. Databases (RDS, DynamoDB, ElastiCache)

**Criteria:** CC6.1, CC6.6, CC6.7, CC7.5, CC9.1

| ID | Title / summary |
|---|---|
| CC6.1 | Implement logical access security over protected information assets (includes encryption of data at rest). |
| CC6.6 | Implement logical access security measures to protect against threats from sources outside the system boundaries. |
| CC6.7 | Restrict and protect the transmission, movement, and removal of information. |
| CC7.5 | Identify, develop, and implement activities to recover from identified security incidents. |
| CC9.1 | Identify, select, and develop risk mitigation activities for risks arising from potential business disruptions. |

**Why it matters:** Databases hold the data a SOC 2 report is ultimately about. A
publicly accessible RDS instance is the database equivalent of an open security
group (CC6.6); an unencrypted instance, cluster or cache is a CC6.1 data-at-rest gap;
plaintext connections to a cache are a CC6.7 transmission gap; and a manual RDS
snapshot shared with "all" hands a full copy of the data to any AWS account (CC6.6
and CC6.7 together). Backups, point-in-time recovery and deletion protection are
the recovery side: CC7.5 requires the ability to restore after an incident such as
ransomware or a destructive change, and CC9.1 covers business-disruption risk. If
the report also covers the Availability category, these backup findings map to
A1.2 as well.

**AWS evidence that would satisfy it:**
- No RDS instance with `PubliclyAccessible=true`; databases in private subnets — `rds_instance_not_public`
- RDS instances and clusters encrypted at rest — `rds_storage_encrypted`
- Automated backups kept ≥ 7 days (or the retention the backup policy sets) — `rds_backup_retention_7d`
- Deletion protection on production databases — `rds_deletion_protection`
- No manual RDS snapshot with `restore=all` — `rds_snapshot_not_public`
- DynamoDB point-in-time recovery on — `dynamodb_pitr_enabled`
- ElastiCache encrypted at rest and in transit (`required` mode), with AUTH or RBAC — `elasticache_encryption_at_rest`, `elasticache_encryption_in_transit`
- Evidence that restores are tested (a dated restore test record) — manual

---

## 9. Encryption & Secrets (KMS, Secrets Manager, EBS, resource policies)

**Criteria:** CC6.1, CC6.3, CC6.6, CC6.7

| ID | Title / summary |
|---|---|
| CC6.1 | Implement logical access security over protected information assets (includes encryption and key management). |
| CC6.3 | Authorize, modify, or remove access based on roles and responsibilities, using least privilege. |
| CC6.6 | Implement logical access security measures to protect against threats from sources outside the system boundaries. |
| CC6.7 | Restrict and protect the transmission, movement, and removal of information. |

**Why it matters:** Encryption only protects data if the keys are managed: CC6.1
points of focus include key generation, rotation and protection. Unrotated KMS keys
and unrotated secrets (database passwords, API keys) extend the life of any
credential that leaks. EBS encryption by default makes encryption the account's
baseline rather than a per-volume decision. A resource policy that allows
`Principal: "*"` with no condition — on a KMS key, secret, ECR repository or SNS
topic — grants access outside the system boundary (CC6.6) and outside any
role-based design (CC6.3); a publicly restorable EBS snapshot is an exfiltration
path (CC6.7).

**AWS evidence that would satisfy it:**
- Automatic rotation on customer-managed symmetric KMS keys — `kms_cmk_rotation_enabled`
- Secrets Manager rotation on, or a documented manual rotation for secrets that can't rotate automatically — `secrets_rotation_enabled`
- No KMS key, secret, ECR repository or SNS topic policy allowing unrestricted `Principal: "*"` — `resource_policy_no_public_principal`
- EBS encryption by default on in every region, and no unencrypted volumes — `ebs_default_encryption`, `ebs_volume_encrypted`
- No publicly restorable EBS snapshot; snapshot Block Public Access set to `block-all-sharing` — `ebs_snapshot_not_public`
- Key policies granting administration and usage to separate roles — manual

---

## 10. Containers (ECR)

**Criteria:** CC7.1, CC8.1

| ID | Title / summary |
|---|---|
| CC7.1 | Use detection and monitoring procedures to identify susceptibilities to newly discovered vulnerabilities. |
| CC8.1 | Authorize, design, develop or acquire, configure, document, test, approve, and implement changes to infrastructure, data, software, and procedures. |

**Why it matters:** For a container workload, the image is the software. Scanning
images on push and continuously (Inspector enhanced scanning) is the CC7.1
vulnerability-identification control for that software. Immutable tags make an
image tag point at one tested build for good, so what was approved under CC8.1 is
what runs; a mutable `:latest` can be overwritten after approval without any
change record.

**AWS evidence that would satisfy it:**
- Every repository covered by enhanced scanning or scan-on-push — `ecr_image_scanning`
- Image tags immutable — `ecr_tag_immutability`
- No repository policy allowing `Principal: "*"` — `resource_policy_no_public_principal`
- Evidence that critical and high image findings are remediated within a defined time — manual

---

## 11. Regional Footprint

**Criteria:** CC6.1

**Why it matters:** CC6.1's points of focus include identifying and managing the
inventory of information assets. An entity that says it operates in two regions
but has an instance, a bucket or an open security group in a third has assets
outside its inventory, and outside the monitoring, patching and change control
built around the regions it knows about. A region nobody uses is also where an
attacker with stolen credentials goes to run resources unseen. Auditors ask
which regions are in use and look for anything outside them.

**AWS evidence that would satisfy it:**
- The operating regions, confirmed with the client and recorded in
  `engagement-info.md` — manual
- Nothing outside those regions apart from AWS-created defaults, or an owner
  and a reason for what is there — `resources_outside_operating_regions`
- An organization SCP denying the unused regions (`aws:RequestedRegion`), confirmed
  from the management account — `region_deny_scp` in the exceptions file

With operating regions declared, the Detection & Monitoring checks above still
report every collected region, but a gap outside the operating regions is an
Informational advisory, communicated to management rather than blocking a pass:
the service is still worth running there to catch misuse, unless an SCP denies
the region.

---

## Sources

- [Secureframe — SOC 2 Common Criteria](https://secureframe.com/hub/soc-2/common-criteria)
- [Scrut.io — SOC 2 Common Criteria](https://www.scrut.io/hub/soc-2/soc-2-common-criteria)
- [Hicomply — SOC 2 Controls CC6: Logical & Physical Access](https://www.hicomply.com/hub/soc-2-controls-cc6-logical-and-physical-access-controls)
- [Hicomply — SOC 2 Controls CC7: System Operations](https://www.hicomply.com/en-us/hub/soc-2-controls-cc7-system-operations)
- [Cyberday.ai — CC7.2: Monitoring of system components for anomalies](https://www.cyberday.ai/requirement/soc-2-cc7-2-monitoring-of-system-components-for-anomalies)
- [Cyberday.ai — CC6.7: Restriction and protection of information in transmission, movement or removal](https://www.cyberday.ai/requirement/soc-2-cc6-7-restriction-and-protection-of-information-in-transmission-movement-or-removal)
- [Cyberday.ai — CC6.5: Discontinuation of logical/physical protections when no longer required](https://www.cyberday.ai/requirement/soc-2-cc6-5-discontinuation-of-logical-physical-protections-when-no-longer-required)
- [Cyberday.ai — CC6.4: Physical access control to facilities and protected information assets](https://www.cyberday.ai/requirement/soc-2-cc6-4-physical-access-control-to-facilities-and-protected-information-assets)
- [Cyberday.ai — CC6.1b: Logical access control for protected information assets](https://www.cyberday.ai/requirement/soc-2-cc6-1b-logical-access-control-for-protected-information-assets)
- [soc2auditors.org — SOC 2 Security Controls (2026): CC6 & CC7 Explained](https://soc2auditors.org/insights/soc-2-security-controls/)
- [AICPA & CIMA — 2017 Trust Services Criteria (with Revised Points of Focus, 2022)](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022) (official source document)
- [Mapping AWS Controls to SOC 2 — Linford & Co.](https://linfordco.com/blog/mapping-aws-controls-soc-2/) (referenced; page blocked direct fetch, cited via search)

**Note:** Criteria titles above are paraphrased/summarized from the 2017 AICPA TSC
framework as reflected in the secondary sources cited. For an authoritative,
word-for-word citation in a compliance deliverable, verify final wording against the
official AICPA & CIMA "2017 Trust Services Criteria" PDF linked above.
