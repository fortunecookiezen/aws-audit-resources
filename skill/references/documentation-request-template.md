# Documentation request: known exceptions and administrative access

Send this to the account/engagement owner before or at the start of an
audit (see `accepting-findings-process.md`, "Before the audit: request
documentation up front"). The goal is to capture what's *already known and
intentional* — centrally-managed root credentials, named admin roles,
anything else you'd otherwise discover as a false positive after the
report is written — so it can go into the exceptions file from the first
run instead of a correction pass. Delete this intro paragraph and the
instructions in *italics* before sending; everything else is meant to be
filled in and returned.

Answers here transcribe directly into `exceptions.json` — see
`exceptions-and-exclusions.md` for the schema each section below maps to.

---

## 1. Engagement information

| Field | Response |
|---|---|
| AWS Account ID(s) in scope | |
| Framework being audited (CIS / Well-Architected / SOC 2 / ISO 27001) | |
| Requested by (auditor name) | |
| Request date | |
| Response due date | |
| Completed by (name, title) | |
| Response date | |

## 2. AWS Organizations root access management

*Root Access Management is the AWS Organizations feature that lets a
management account delete/disable a member account's root password, access
keys, and MFA devices entirely. If it's enabled for this account, say so
here — `run_checks.py` can otherwise only detect it automatically when the
audit role runs with management-account or delegated-admin privileges,
which most audits don't have.*

| Question | Response |
|---|---|
| Is this account part of an AWS Organization? | Yes / No / Unsure |
| If yes, is centralized Root Access Management (`RootCredentialsManagement`) enabled for this account? | Yes / No / Unsure |
| Who can independently confirm this from the Organizations management account (name, how to reach them)? | |
| Evidence attached or referenced (`aws iam list-organizations-features` output, console screenshot, ticket) | |
| What is this account's expected root-credential review cadence, if root is *not* centrally managed (e.g. quarterly = 90 days, annual = 365 days)? | |
| Is there any legitimate, expected root-account usage (e.g. a documented break-glass procedure)? If so, describe it. | |

## 3. Known administrator / full-access roles and users

*List every IAM role, user, or group you already know holds
`AdministratorAccess` or an equivalent full-admin (`Action: *`,
`Resource: *`) policy, and why. Add rows as needed. An AWS-generated name
with a random suffix (an IAM Identity Center permission set role, a
CloudFormation StackSets execution role, etc.) should be given as a prefix
or pattern rather than the exact current name, since the suffix changes if
the role is recreated.*

| Role/user name or pattern | Policy held | Purpose / justification | Owner / approver | Last reviewed | Review cadence |
|---|---|---|---|---|---|
| | | | | | |
| | | | | | |
| | | | | | |

Common categories to check for, even if you don't think of them as
"administrator roles" at first:

- IAM Identity Center (SSO) permission sets named `AdministratorAccess` or
  similar (`AWSReservedSSO_<name>_<hash>`)
- `OrganizationAccountAccessRole` (created automatically in every member
  account of an AWS Organization)
- CloudFormation StackSets execution roles (`stacksets-exec-<hash>`)
- CI/CD or infrastructure-as-code deployment roles (Terraform, CDK, etc.)
- Named break-glass / emergency-access roles
- Any third-party vendor or MSP role with broad access

## 4. Other known, already-accepted risks or compensating controls

*Anything else you know this audit is likely to flag, that's already been
reviewed and accepted for a specific reason — not limited to root or IAM
findings.*

| Finding / control area | What's expected to be flagged | Compensating control or justification | Owner / approver | Review date |
|---|---|---|---|---|
| | | | | |
| | | | | |

## 5. Security and compliance contacts

| Role | Name | Contact |
|---|---|---|
| Account/engagement owner | | |
| Security contact | | |
| Compliance/audit contact | | |

## 6. Sign-off

By completing this document, I confirm the information above is accurate
to the best of my knowledge as of the response date, and understand that
items listed here will be recorded as explicit, attributed exceptions in
the audit's evidence package (not hidden from the report) — see
`exceptions-and-exclusions.md`, "What 'accepted' means in the output."

| | |
|---|---|
| Name | |
| Title | |
| Date | |
