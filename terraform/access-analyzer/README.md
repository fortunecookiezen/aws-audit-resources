# access-analyzer

Terraform equivalent of [`cloudformation/create_account_access_analyzer.yml`](../../cloudformation/create_account_access_analyzer.yml). Creates an IAM Access Analyzer with the organization as its zone of trust (`ORGANIZATION`), and optionally an organization unused access analyzer.

Prerequisites: trusted access for IAM Access Analyzer must be enabled in AWS Organizations, and you must apply this module with credentials for the organization's management account or the Access Analyzer delegated administrator account.

Access Analyzer is regional. Apply this module in every region you use to get full external access coverage, for example with one provider configuration per region (see the multi-region example in the [Terraform README](../README.md#applying-in-several-regions)).

## Unused access analyzer (paid, off by default)

Set `enable_unused_access_analyzer = true` to also create an `ORGANIZATION_UNUSED_ACCESS` analyzer. It reports unused IAM roles, unused IAM user access keys and passwords, and unused permissions across every account in the organization. `unused_access_age_days` (default `90`) sets how long something must go unused before it is reported.

> [!WARNING]
> The unused access analyzer is a paid feature, billed monthly per IAM role and IAM user analyzed across all member accounts, for each unused access analyzer you create. Estimate the cost with the [IAM Access Analyzer pricing page](https://aws.amazon.com/iam/access-analyzer/pricing/) before enabling it. IAM is global, so enable it in only one region: turning it on in every region multiplies the charge without adding findings.

## Example

```hcl
module "access_analyzer" {
  source = "github.com/fortunecookiezen/aws-audit-resources//terraform/access-analyzer"
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
| [aws_accessanalyzer_analyzer.organization](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/accessanalyzer_analyzer) | resource |
| [aws_accessanalyzer_analyzer.organization_unused_access](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/accessanalyzer_analyzer) | resource |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| analyzer\_name | Name of the external access analyzer. | `string` | `"OrganizationAccessAnalyzer"` | no |
| enable\_unused\_access\_analyzer | Also create an unused access analyzer, which reports unused IAM roles, unused IAM user access keys and<br/>passwords, and unused permissions across every account in the organization. WARNING: this is a PAID<br/>feature, billed monthly per IAM role and IAM user analyzed across all member accounts, for each unused<br/>access analyzer you create. Estimate the cost before enabling it<br/>(https://aws.amazon.com/iam/access-analyzer/pricing/). IAM is global, so enable this in only one region -<br/>enabling it in every region where you deploy this module multiplies the charge for no additional findings. | `bool` | `false` | no |
| tags | Tags to apply to the analyzers. None are applied by default. | `map(string)` | `{}` | no |
| unused\_access\_age\_days | Number of days without use after which a role, credential, or permission is reported as unused.<br/>Ignored unless enable\_unused\_access\_analyzer is true. | `number` | `90` | no |
| unused\_access\_analyzer\_name | Name of the unused access analyzer. Ignored unless enable\_unused\_access\_analyzer is true. | `string` | `"OrganizationUnusedAccessAnalyzer"` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| organization\_access\_analyzer\_arn | Organization Access Analyzer ARN |
| organization\_unused\_access\_analyzer\_arn | Organization Unused Access Analyzer ARN, or null if enable\_unused\_access\_analyzer is false |
<!-- END_TF_DOCS -->
