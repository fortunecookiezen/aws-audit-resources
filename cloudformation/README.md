# Cloudformation Templates for security and audit functions in an AWS Account

## security-audit-role.yml

This role incorporates the following AWS Managed permissions to allow access to review service configurations in support of a security reviewer or audit function. This stack is intended to be deployed to support role assumption from a trusted or a centralized IAM account.

- `arn:aws:iam::aws:policy/AmazonInspector2ReadOnlyAccess`
- `arn:aws:iam::aws:policy/AWSSecurityHubReadOnlyAccess`
- `arn:aws:iam::aws:policy/SecurityAudit`
- `arn:aws:iam::aws:policy/job-function/ViewOnlyAccess`

It also grants a supplemental inline read-only policy (`SupplementalReadOnlyAccess`) covering services not fully captured by the managed policies above: notifications, IAM Access Analyzer, Service Discovery, GuardDuty/Macie/Shield/WAFv2/ECR describe-level access, CloudTrail, CodeStar-family services, account/billing/cost visibility, and AI service usage auditing (Bedrock, Bedrock AgentCore, Q Business, Q Developer/CodeWhisperer).

### Trust policy

The trust policy allows `sts:AssumeRole` from principals in the account identified by the `PrincipalAccountId` parameter (via the `aws:PrincipalAccount` condition, since AWS IAM Identity Center permission set role ARNs contain a generated path segment that can't be referenced directly as an IAM `Principal`). Two additional parameters narrow this further:

- **`TrustedPrincipalArnPattern`** (required) — an `aws:PrincipalArn` `StringLike` pattern that restricts assumption to a specific SSO permission set or role, e.g. `arn:aws:iam::<PrincipalAccountId>:role/aws-reserved/sso.amazonaws.com/*/AWSReservedSSO_YourPermissionSetName_*`. Pass `"*"` only if you intentionally want to trust every IAM principal in the account.
- **`RequireMFA`** (default `"true"`) — adds an `aws:MultiFactorAuthPresent` condition. Only leave this as `"true"` if your identity provider/IAM Identity Center actually propagates MFA status on the sessions it issues; otherwise set it to `"false"` to avoid locking yourself out.

**`MaxSessionDurationSeconds`** (default `3600`, 3600–43200) sets the role's `MaxSessionDuration`.

### Notes

- Audit Manager access was removed (the service is being discontinued); the supplemental policy was renamed from `AuditManagerReadOnlyAccess` accordingly, since it's now read-only end to end.
- The legacy `aws-portal:View*` billing action was replaced with the current fine-grained `account`/`billing`/`ce`/`consolidatedbilling`/`cur`/`freetier`/`invoicing`/`payments`/`tax` service actions.
- The stack output is `SecurityAuditRoleArn` (previously the misleadingly named `RootAdminRoleArn`).

## security-support-role.yml

This role is suitable for a security consultant or manager who needs read access to many resources and the ability to configure AWS Audit Manager and respond or file support cases (such as during an incident). This stack is intended to be deployed to support role assumption from a trusted or a centralized IAM account.

- `arn:aws:iam::aws:policy/AmazonInspector2ReadOnlyAccess`
- `arn:aws:iam::aws:policy/AWSAuditManagerAdministratorAccess`
- `arn:aws:iam::aws:policy/AWSSecurityHubReadOnlyAccess`
- `arn:aws:iam::aws:policy/ReadOnlyAccess`
- `arn:aws:iam::aws:policy/SecurityAudit`
