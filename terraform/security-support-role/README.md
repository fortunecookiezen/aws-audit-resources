# security-support-role

Terraform equivalent of [`cloudformation/security-support-role.yml`](../../cloudformation/security-support-role.yml). Creates `<org_prefix>-CrossAccountSecuritySupportRole` for incident investigation and handling: broad read access, AWS Support case management, and a curated set of containment actions. It is deliberately not AdministratorAccess. It assumes an account administrator is available for anything beyond first-response containment.

Apply it in each target/member account. IAM is global, so apply it once per account, not once per region.

The role gets the `AmazonInspector2ReadOnlyAccess`, `AWSSecurityHubReadOnlyAccess`, `AWSSupportAccess`, `ReadOnlyAccess` and `SecurityAudit` managed policies, plus the `IncidentResponseContainment` inline policy. See the [CloudFormation README](../../cloudformation/README.md#containment-permissions-security-support-role-incidentresponsecontainment-inline-policy) for what each containment statement allows and deliberately leaves out.

> [!IMPORTANT]
> Leave `require_mfa` set to `false` if your workforce users sign in through AWS IAM Identity Center. Identity Center sessions never carry `aws:MultiFactorAuthPresent`, so `true` locks every SSO user out of the role. Enforce MFA at Identity Center sign-in instead.

## Example

```hcl
module "security_support_role" {
  source = "github.com/fortunecookiezen/aws-audit-resources//terraform/security-support-role"

  principal_account_id          = "111111111111"
  trusted_principal_arn_pattern = "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_IncidentResponse_*"
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
| [aws_iam_role_policy.incident_response_containment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy_attachment.managed](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| principal\_account\_id | 12 digit id of the account containing the users to which you're granting access. | `string` | n/a | yes |
| trusted\_principal\_arn\_pattern | IAM principal ARN pattern (matched with a StringLike condition) within principal\_account\_id that is<br/>allowed to assume this role. Scope this to the specific SSO permission set or role you use for<br/>incident-response work, rather than trusting every IAM principal in the account, e.g.<br/>`arn:aws:iam::{principal_account_id}:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_YourPermissionSetName_*`<br/>Pass `"*"` only if you intentionally want to trust every IAM principal in principal\_account\_id. | `string` | n/a | yes |
| iam\_quarantine\_policy\_arn | Managed policy this role is permitted to attach to a suspected-compromised IAM user or role in order to<br/>contain it. Defaults (when null) to the AWS-maintained AWSCompromisedKeyQuarantineV3 policy, which denies<br/>privilege-escalation and abuse-enabling actions (attaching/creating policies, creating access keys,<br/>PassRole, RunInstances, CreateBucket, etc.) without removing the identity or its existing access for<br/>forensic review. Override only if your organization maintains its own quarantine policy. | `string` | `null` | no |
| max\_session\_duration\_seconds | Maximum session duration, in seconds, for role sessions. Must be between 3600 (1 hour) and 43200 (12 hours). | `number` | `3600` | no |
| org\_prefix | Organizational prefix for resources. The role is named {org\_prefix}-CrossAccountSecuritySupportRole. | `string` | `"opspath"` | no |
| require\_mfa | Require aws:MultiFactorAuthPresent on the calling session to assume this role. Must be false if your<br/>workforce users access AWS through AWS IAM Identity Center: Identity Center sessions never carry<br/>aws:MultiFactorAuthPresent (enforce MFA at Identity Center sign-in instead), so true locks every SSO<br/>user out of the role. Only set to true for IAM users or federated principals whose sessions are issued<br/>with MFA context (e.g. sts:GetSessionToken with an MFA device). | `bool` | `false` | no |
| tags | Tags to apply to the role. None are applied by default. | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| security\_support\_role\_arn | CrossAccountSecuritySupportRole role ARN |
<!-- END_TF_DOCS -->
