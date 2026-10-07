# AWS Security Audit → ISO/IEC 27001:2022 Annex A Control Mapping

Reference mapping for an AWS account security audit skill. Scope is limited to six technical areas: IAM, MFA, S3 bucket security, CloudTrail/logging & monitoring, Security Groups/VPC network exposure, and root account protections. Annex A control numbers and titles below are from the current ISO/IEC 27001:2022 Annex A control set (93 controls across the Organizational, People, Physical, and Technological themes; this scope only touches the Organizational and Technological themes).

---

## 1. IAM (users, policies, password policy, access keys, root account usage)

### A.5.15 — Access control
**Why it matters:** This is the umbrella control requiring that rules for controlling physical and logical access to information and assets be established and enforced based on business and security requirements. Every IAM policy, group, and permission boundary in an AWS account is an implementation of this control.
**AWS evidence:** IAM policies (managed/inline) attached to users, groups, and roles; permission boundaries; SCPs at the Organizations level; documented least-privilege policy design (no `*:*` policies attached directly to users); evidence that access is granted based on job role rather than ad hoc.

### A.5.16 — Identity management
**Why it matters:** Requires that the full lifecycle of identities be managed — identities must be uniquely attributable to a person or system, and unused or duplicate identities must not persist.
**AWS evidence:** IAM users mapped 1:1 to individuals (no shared/generic accounts); use of IAM Identity Center (SSO) or federated identities rather than long-lived local IAM users where feasible; inventory of IAM users with creation date and last-activity timestamp; evidence of deprovisioning (deleted/disabled users) tied to offboarding.

### A.5.17 — Authentication information
**Why it matters:** Governs how authentication information (passwords, keys, secrets) is allocated, managed, and protected throughout its lifecycle, including requirements for complexity and rotation.
**AWS evidence:** IAM account password policy (`GetAccountPasswordPolicy`) — minimum length, complexity flags, password reuse prevention, expiration/rotation period; IAM access key age (`GetCredentialReport` / `list-access-keys`) showing keys rotated within a defined period (e.g., 90 days); no hard-coded credentials in code (Access Analyzer / Secrets Manager usage as compensating evidence).

### A.5.18 — Access rights
**Why it matters:** Requires access rights to be provisioned, reviewed, and revoked in line with the access control policy — including periodic recertification and prompt removal on role change or termination.
**AWS evidence:** IAM Access Analyzer findings; evidence of periodic access reviews (e.g., unused permissions/last-accessed data via IAM Access Advisor); no unused/stale IAM users or roles beyond a defined threshold (e.g., 90 days inactive); removal of default/legacy overly-permissive policies (e.g., `AdministratorAccess` attached broadly).

### A.8.2 — Privileged access rights
**Why it matters:** Requires the allocation and use of privileged access rights to be restricted and managed, since compromise of a privileged identity has outsized impact.
**AWS evidence:** Number and list of IAM principals with `AdministratorAccess` or equivalent broad policies; use of IAM roles + temporary STS credentials for admin tasks rather than standing privileged IAM users; separation of a break-glass admin identity from day-to-day accounts.

### A.8.3 — Information access restriction
**Why it matters:** Requires that access to information and application system functions be restricted per the access control policy — the technical enforcement layer beneath A.5.15/A.5.18.
**AWS evidence:** Resource-based policies and condition keys (e.g., `aws:SourceIp`, `aws:MultiFactorAuthPresent`) restricting when/how IAM permissions can be used; deny policies blocking actions outside approved regions or without MFA.

### A.8.5 — Secure authentication
**Why it matters:** Requires secure authentication technologies and procedures (strong credentials, MFA, protection against brute force) based on the sensitivity of what is being accessed.
**AWS evidence:** IAM password policy enforcing complexity; console access requiring MFA (see Area 2 below); no active root or IAM console access keys older than policy allows; CloudTrail evidence of failed console login throttling/lockout behavior.

---

## 2. MFA (root and IAM users)

### A.8.5 — Secure authentication
**Why it matters:** This is the primary control for MFA — it explicitly calls for secure authentication technologies and procedures proportionate to the sensitivity of the information being accessed, and multi-factor authentication is the standard implementation for privileged and console access.
**AWS evidence:** `GetAccountSummary` / IAM credential report showing MFA enabled for the root account and for every IAM user with console access; MFA device type (virtual, hardware/FIDO2, or U2F) meeting policy; SSO/Identity Center MFA enforcement for federated users.

### A.5.17 — Authentication information
**Why it matters:** MFA devices/tokens are themselves authentication information whose issuance, protection, and revocation must be managed — e.g., ensuring a departing employee's MFA device is deregistered.
**AWS evidence:** Record of MFA device deregistration tied to the offboarding process; no orphaned virtual MFA devices assigned to deleted/disabled users.

### A.8.2 — Privileged access rights
**Why it matters:** Root and admin-equivalent IAM identities are the highest-value privileged accounts in the account; MFA on these is a direct control against credential-theft-driven privilege escalation.
**AWS evidence:** Root account MFA status (hardware MFA recommended for root); MFA enforced via IAM policy condition (`aws:MultiFactorAuthPresent`) for any IAM principal performing privileged/destructive actions.

---

## 3. S3 Bucket Security (public access, encryption, logging)

### A.5.15 — Access control
**Why it matters:** Bucket policies, ACLs, and Block Public Access settings are the access control mechanism governing who can read/write S3 data; misconfiguration here is one of the most common cloud breach vectors.
**AWS evidence:** S3 Block Public Access enabled at account level and per bucket; no bucket policy or ACL granting `Principal: "*"` or `AllUsers`/`AuthenticatedUsers` access; Access Analyzer for S3 findings showing no externally accessible buckets (unless explicitly intended, e.g., static website hosting, with compensating controls documented).

### A.8.3 — Information access restriction
**Why it matters:** Beyond "public or not," this control covers restricting access to the specific principals/roles that need it — the least-privilege layer of bucket access.
**AWS evidence:** Bucket policies scoped to specific IAM roles/accounts/VPC endpoints (e.g., `aws:SourceVpce` conditions); cross-account access reviewed and justified; no wildcard `Principal` in policies granting write/delete.

### A.8.24 — Use of cryptography
**Why it matters:** Requires appropriate use of encryption to protect confidentiality and integrity of information based on classification and risk.
**AWS evidence:** Default encryption enabled on every bucket (SSE-S3, SSE-KMS, or SSE-C); for sensitive data, SSE-KMS with customer-managed keys and key rotation enabled; bucket policies enforcing `aws:SecureTransport` (TLS in transit) via deny-if-not-HTTPS statements.

### A.8.12 — Data leakage prevention
**Why it matters:** Requires measures to detect and prevent unauthorized disclosure of sensitive information — public S3 buckets are a canonical data-leakage scenario.
**AWS evidence:** Macie findings (if enabled) for sensitive data in buckets; S3 Storage Lens / Access Analyzer flags for public or cross-account exposure; alerting configured for changes to bucket public-access settings (e.g., EventBridge rule on `PutBucketPolicy`/`PutBucketAcl`).

### A.8.15 — Logging
**Why it matters:** Requires logs of events (access, changes, errors) to be produced, retained, and protected — for S3 this means knowing who accessed or modified objects and bucket configuration.
**AWS evidence:** S3 server access logging enabled and delivered to a dedicated, access-restricted logging bucket; S3 data events captured in CloudTrail (object-level logging) for sensitive buckets; log bucket itself has Block Public Access and restrictive policy.

---

## 4. CloudTrail / Logging & Monitoring

### A.8.15 — Logging
**Why it matters:** The core control requiring that logs recording activities, exceptions, and security events be produced and kept — CloudTrail is AWS's primary implementation of this for API/control-plane activity.
**AWS evidence:** CloudTrail enabled in all regions (multi-region trail); trail covers management events (read+write) and, where relevant, data events for S3/Lambda; logs delivered to a dedicated S3 bucket (and/or CloudWatch Logs) with restrictive access; log file validation enabled (`--enable-log-file-validation`) to detect tampering.

### A.5.28 — Collection of evidence
**Why it matters:** Requires procedures for identification, collection, and preservation of evidence related to security events — CloudTrail logs, when protected from tampering/deletion, serve as this evidentiary record.
**AWS evidence:** CloudTrail log file integrity validation enabled; log bucket has versioning + MFA delete or Object Lock (WORM) to prevent deletion/alteration; log retention period defined and met (e.g., via S3 lifecycle policy) consistent with incident response/legal needs.

### A.8.16 — Monitoring activities
**Why it matters:** Requires networks, systems, and applications to be monitored for anomalous behavior, and requires that mechanisms exist to evaluate and act on potential incidents — not just collect logs, but review and alert on them.
**AWS evidence:** CloudWatch alarms / EventBridge rules on high-risk CloudTrail events (root login, IAM policy changes, security group changes, disabling of CloudTrail itself); GuardDuty enabled and findings triaged; AWS Config rules evaluating resource compliance drift; Security Hub aggregating findings.

### A.8.17 — Clock synchronization
**Why it matters:** Requires clocks of information processing systems to be synchronized to an approved time source, since accurate timestamps are essential for correlating logs during an investigation.
**AWS evidence:** CloudTrail/CloudWatch timestamps are AWS-managed (inherently synchronized); for any self-managed EC2 instances in scope, confirm NTP/Amazon Time Sync Service is configured so instance-level logs correlate accurately with CloudTrail.

### A.8.9 — Configuration management
**Why it matters:** Requires that configurations (including security configurations) of hardware, software, and services be established, documented, and monitored for unauthorized change — applies to the logging/monitoring configuration itself (e.g., ensuring CloudTrail isn't silently disabled).
**AWS evidence:** AWS Config recorder enabled and tracking CloudTrail/GuardDuty/Config-itself as monitored resources; alerting on `StopLogging`, `DeleteTrail`, or `UpdateTrail` CloudTrail API calls; baseline security configuration documented and periodically reconciled via Config conformance packs.

---

## 5. Security Groups / VPC Network Exposure

### A.8.20 — Networks security
**Why it matters:** Requires networks and network devices to be secured, managed, and controlled to protect information in systems and applications — Security Groups and NACLs are AWS's implementation of network access control.
**AWS evidence:** No security group with an inbound rule allowing `0.0.0.0/0` (or `::/0`) on sensitive ports (22, 3389, database ports, etc.); default VPC security group left with no rules or clearly documented if used; NACLs reviewed for overly permissive allow-all rules; VPC Flow Logs enabled to record traffic for review.

### A.8.21 — Security of network services
**Why it matters:** Requires that security mechanisms, service levels, and management requirements for network services be identified and included in agreements — for AWS this covers how managed network services (ELB, NAT Gateway, VPC endpoints, Direct Connect/VPN) are configured securely.
**AWS evidence:** Load balancers configured with TLS listeners (no plaintext where avoidable) and up-to-date security policies; VPC endpoints (Interface/Gateway) used for AWS service access instead of routing through the public internet where feasible; bastion/jump host or Session Manager used instead of direct public SSH/RDP exposure.

### A.8.22 — Segregation of networks
**Why it matters:** Requires groups of information services, users, and systems to be segregated on separate networks — reducing blast radius if one segment is compromised.
**AWS evidence:** Use of multiple VPCs or subnets to separate tiers (public/web, application, data) and environments (prod/non-prod); private subnets for databases/backend with no direct route to an Internet Gateway; security group references (rather than broad CIDR ranges) used to control tier-to-tier traffic; separate accounts/OUs per environment via AWS Organizations as a stronger form of segregation.

### A.8.9 — Configuration management
**Why it matters:** Network security configuration (security groups, NACLs, route tables) must be established per a documented baseline and monitored for unauthorized drift.
**AWS evidence:** AWS Config rules such as `restricted-ssh`, `restricted-common-ports`, `vpc-sg-open-only-to-authorized-ports`; alerting on `AuthorizeSecurityGroupIngress`/`ModifyNetworkAcl` API calls via CloudTrail/EventBridge; infrastructure-as-code (Terraform/CloudFormation) managing security groups with change review, rather than ad hoc console edits.

---

## 6. Root Account Protections

### A.8.2 — Privileged access rights
**Why it matters:** The AWS root user is the ultimate privileged identity — it cannot be permission-restricted and can bypass most guardrails, so this control's requirement to strictly manage privileged access applies most acutely here.
**AWS evidence:** Root account not used for day-to-day operations (CloudTrail shows no/minimal root login events post-setup); root access keys deleted (root should have no active access keys); IAM users/roles with `AdministratorAccess` used instead for admin tasks; AWS Organizations/SCPs restricting root actions in member accounts.

### A.8.5 — Secure authentication
**Why it matters:** Root, having no permission boundary, must have the strongest authentication protections available.
**AWS evidence:** Root MFA enabled, ideally with a hardware/FIDO2 security key rather than a virtual MFA app; strong, unique root password not shared or reused; root email address monitored and protected (e.g., a distribution list with controlled access, not a single individual's inbox).

### A.5.17 — Authentication information
**Why it matters:** Root credentials (password, MFA device, recovery email/phone) are the most sensitive authentication information in the account and must be governed with the strictest lifecycle protection.
**AWS evidence:** Root credentials stored securely (e.g., in a sealed/break-glass process or enterprise password vault) rather than known to multiple individuals informally; documented break-glass procedure for root use including post-use password rotation.

### A.5.18 — Access rights
**Why it matters:** Requires access rights (including the root identity's implicit "rights") to be reviewed periodically — for root this means periodically re-verifying that root is not being used operationally and that break-glass access is still appropriately restricted.
**AWS evidence:** Periodic review/attestation that root is unused for operational tasks (CloudTrail root-usage report); alert configured (CloudWatch/EventBridge) on any `ConsoleLogin` or API call by the root principal, routed to security team for immediate review.

---

## Sources

- [ISO 27001 Annex A Controls List: All 93 Controls by Theme — gaicc.org](https://gaicc.org/blog/iso-27001-annex-a-controls-list/)
- [ISO 27001:2022 Annex A Controls List — Scrut](https://www.scrut.io/hub/iso-27001/iso-27001-controls)
- [Understanding ISO 27001 Controls: A Guide to Annex A — Drata](https://drata.com/learn/iso-27001/controls-annex-a)
- [ISO 27001 Controls List: Complete Annex A Framework & Guide — Hightable](https://hightable.io/iso-27001-controls/)
- [ISO 27001 Controls: Overview of all measures from Annex A — DataGuard](https://www.dataguard.com/iso-27001/annex-a/)
- [ISO 27001 Controls: A Guide to Implementing Annex A Controls — Sprinto](https://sprinto.com/blog/iso-27001-controls/)
- [ISO 27001 Annex A Controls Explained: All 93 Controls Overview — Glocert International](https://www.glocertinternational.com/resources/articles/iso-27001-annex-a-controls-explained/)
- [ISO 27001 Annex A Controls Explained: All 93 Controls — Standarity](https://standarity.com/blog/iso-27001-annex-a-controls-explained)
- [Practical Advice for Locking Down the Network with ISO 27001 Controls A.8.20–A.8.22 — DQS](https://www.dqsglobal.com/en/explore/blog/practical-advice-for-locking-down-the-network-with-iso-27001-controls-a.8.20%E2%80%93a.8.22)
- [ISO 27001 Annex A 8.21 Security of Network Services Explained — Hightable](https://hightable.io/iso27001-annex-a-8-21-security-of-network-services/)
- [ISO 27001 Network Security Explained (Annex A 8.20) — Hightable](https://hightable.io/iso27001-annex-a-8-20-network-security/)
- [ISO 27001:2022 Annex A 8.20/8.21 — Pretesh Biswas](https://preteshbiswas.com/2023/01/23/iso-270012022-a-8-20-networks-security-a-8-21-security-of-network-services/)

*Note: Control numbers/titles were verified via multiple independent sources listing the full current ISO/IEC 27001:2022 Annex A control set (93 controls: 37 Organizational, 8 People, 14 Physical, 34 Technological). For binding compliance use, cross-check against the official ISO/IEC 27001:2022 standard text, which is not freely published online.*
