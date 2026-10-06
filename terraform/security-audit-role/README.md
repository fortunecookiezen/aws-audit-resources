# security-audit-role

Terraform equivalent of [`cloudformation/security-audit-role.yml`](../../cloudformation/security-audit-role.yml). Creates `<org_prefix>-CrossAccountSecurityAuditRole`: a read-only role for security review and audit, assumed cross-account from a trusted or centralized account.

Apply it in each target/member account. IAM is global, so apply it once per account, not once per region.

The role gets the `AmazonInspector2ReadOnlyAccess`, `AWSSecurityHubReadOnlyAccess`, `SecurityAudit` and `job-function/ViewOnlyAccess` managed policies, plus the `SupplementalReadOnlyAccess` inline policy (including `sts:GetCallerIdentity`, needed by the [`skill/`](../../skill/SKILL.md) audit skill's collector to verify the assumed role before collecting data). See the [CloudFormation README](../../cloudformation/README.md#security-audit-roleyml) for what that policy covers and how the trust policy works.

> [!IMPORTANT]
> Leave `require_mfa` set to `false` if your workforce users sign in through AWS IAM Identity Center. Identity Center sessions never carry `aws:MultiFactorAuthPresent`, so `true` locks every SSO user out of the role. Enforce MFA at Identity Center sign-in instead.

## Example

```hcl
module "security_audit_role" {
  source = "github.com/fortunecookiezen/aws-audit-resources//terraform/security-audit-role"

  principal_account_id          = "111111111111"
  trusted_principal_arn_pattern = "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_SecurityAudit_*"
}
```

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
| ---- | ------- |
| terraform | >= 1.5.0 |
| aws | >= 6.0 |

## Providers

| Name | Version |
| ---- | ------- |
| aws | >= 6.0 |

## Resources

| Name | Type |
| ---- | ---- |
| [aws_iam_role.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.supplemental_read_only](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy_attachment.managed](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| principal\_account\_id | 12 digit id of the account containing the users to which you're granting access. | `string` | n/a | yes |
| trusted\_principal\_arn\_pattern | IAM principal ARN pattern (matched with a StringLike condition) within principal\_account\_id that is<br/>allowed to assume this role. Scope this to the specific SSO permission set or role you use for audit<br/>work, rather than trusting every IAM principal in the account, e.g.<br/>`arn:aws:iam::{principal_account_id}:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_YourPermissionSetName_*`<br/>Pass `"*"` only if you intentionally want to trust every IAM principal in principal\_account\_id. | `string` | n/a | yes |
| max\_session\_duration\_seconds | Maximum session duration, in seconds, for role sessions. Must be between 3600 (1 hour) and 43200 (12 hours). | `number` | `7200` | no |
| org\_prefix | Organizational prefix for resources. The role is named {org\_prefix}-CrossAccountSecurityAuditRole. | `string` | `"opspath"` | no |
| require\_mfa | Require aws:MultiFactorAuthPresent on the calling session to assume this role. Must be false if your<br/>workforce users access AWS through AWS IAM Identity Center: Identity Center sessions never carry<br/>aws:MultiFactorAuthPresent (enforce MFA at Identity Center sign-in instead), so true locks every SSO<br/>user out of the role. Only set to true for IAM users or federated principals whose sessions are issued<br/>with MFA context (e.g. sts:GetSessionToken with an MFA device). | `bool` | `false` | no |
| tags | Tags to apply to the role. None are applied by default. | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| security\_audit\_role\_arn | CrossAccountSecurityAuditRole role ARN |
<!-- END_TF_DOCS -->
