# assume-role

Terraform equivalent of [`cloudformation/assume-role.yml`](../../cloudformation/assume-role.yml). Creates an IAM group, named `<group_name>-<region>` to match the CloudFormation template, whose members can `sts:AssumeRole` into the role ARNs you pass in `target_account_role_arns`.

Apply it in the account that holds the IAM users who need to switch roles.

Unlike the CloudFormation template, `target_account_role_arns` has no placeholder default. You must pass at least one real role ARN, so the group can't be created with a policy that grants nothing.

## Example

```hcl
module "assume_role" {
  source = "github.com/fortunecookiezen/aws-audit-resources//terraform/assume-role"

  group_name = "security-auditors"
  target_account_role_arns = [
    "arn:aws:iam::222222222222:role/opspath-CrossAccountSecurityAuditRole",
    "arn:aws:iam::333333333333:role/opspath-CrossAccountSecurityAuditRole",
  ]
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
| [aws_iam_group.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_group) | resource |
| [aws_iam_group_policy.cross_account_access](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_group_policy) | resource |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| group\_name | Name for the group. The current region is appended, e.g. {group\_name}-us-east-1. | `string` | n/a | yes |
| target\_account\_role\_arns | List of IAM role ARNs in other accounts that members of the group may assume. | `list(string)` | n/a | yes |

## Outputs

| Name | Description |
| ---- | ----------- |
| remote\_admin\_assume\_role\_group\_arn | Assume Remote Admin Role Group ARN |
| remote\_admin\_assume\_role\_group\_name | Assume Remote Admin Role Group Name |
<!-- END_TF_DOCS -->
