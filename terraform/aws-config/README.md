# aws-config

Terraform equivalent of [`cloudformation/EnableAWSConfig.yml`](../../cloudformation/EnableAWSConfig.yml). Enables AWS Config in one region: an encrypted S3 delivery bucket with a TLS-only bucket policy, an optional SNS notification topic and email subscription, the Config service-linked role, a configuration recorder, and a delivery channel. Unlike CloudFormation, Terraform needs an explicit `aws_config_configuration_recorder_status` resource to start the recorder, so this module includes one.

AWS Config is regional. Apply this module in each region you want recorded. The service-linked role is global, so when you apply in several regions, set `service_linked_role_region` to one of them so the role is only created once.

## Differences from the CloudFormation template

- **`recording_frequency` is required.** It has no default in the CloudFormation template either. `CONTINUOUS` records every change; `DAILY` costs less but only records once a day.
- **`snapshot_delivery_frequency` takes the AWS values directly** (`One_Hour` … `TwentyFour_Hours`) instead of CloudFormation's `1hour` … `24hours` aliases.
- **Optional inputs use `null` instead of placeholder strings** like `<Generated>`, `<New Topic>`, `<None>` and `<DeployToAnyRegion>`.
- **The S3 bucket has `prevent_destroy = true`.** It's the Terraform equivalent of the template's `DeletionPolicy: Retain` and `UpdateReplacePolicy: Retain`, and protects the recorded configuration history. The difference is that Terraform refuses the plan instead of quietly leaving the bucket behind. To tear the module down and keep the bucket, remove the bucket resources from state first:

  ```bash
  terraform state rm aws_s3_bucket.config \
    aws_s3_bucket_server_side_encryption_configuration.config \
    aws_s3_bucket_policy.config
  terraform destroy
  ```

## Example

```hcl
module "aws_config" {
  source = "github.com/fortunecookiezen/aws-audit-resources//terraform/aws-config"

  recording_frequency = "CONTINUOUS"
  notification_email  = "security-alerts@example.com"
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
| [aws_config_configuration_recorder.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/config_configuration_recorder) | resource |
| [aws_config_configuration_recorder_status.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/config_configuration_recorder_status) | resource |
| [aws_config_delivery_channel.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/config_delivery_channel) | resource |
| [aws_iam_service_linked_role.config](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_service_linked_role) | resource |
| [aws_s3_bucket.config](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket_policy.config](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_policy) | resource |
| [aws_s3_bucket_server_side_encryption_configuration.config](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration) | resource |
| [aws_sns_topic.config](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic) | resource |
| [aws_sns_topic_policy.config](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_policy) | resource |
| [aws_sns_topic_subscription.email](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_subscription) | resource |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| recording\_frequency | The frequency with which the AWS Config recorder records configuration changes: CONTINUOUS or DAILY. | `string` | n/a | yes |
| all\_supported | Indicates whether to record all supported resource types. | `bool` | `true` | no |
| delivery\_channel\_name | The name of the delivery channel. Uses the provider default ("default") when null. | `string` | `null` | no |
| include\_global\_resource\_types | Indicates whether AWS Config records all supported global resource types. | `bool` | `false` | no |
| notification\_email | Email address subscribed to AWS Config notifications. Only used when a new topic is created (sns\_topic\_arn is null). | `string` | `null` | no |
| resource\_types | A list of valid AWS resource types to include in this recording group, such as AWS::EC2::Instance or<br/>AWS::CloudTrail::Trail. Ignored when all\_supported is true. | `list(string)` | `[]` | no |
| service\_linked\_role\_region | A region such as us-east-1. If set, the Config service-linked role is only created when this module is<br/>applied in that region, so deploying to several regions doesn't try to create the (global) role twice.<br/>When null, the role is created in whatever region the module is applied in. | `string` | `null` | no |
| snapshot\_delivery\_frequency | The frequency with which AWS Config delivers configuration snapshots. | `string` | `"TwentyFour_Hours"` | no |
| sns\_topic\_arn | ARN of an existing SNS topic that AWS Config delivers notifications to. A new topic is created when null. | `string` | `null` | no |
| tags | Tags to apply to the S3 bucket, SNS topic, and service-linked role. None are applied by default. | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| config\_bucket\_name | Name of the S3 bucket AWS Config delivers configuration history and snapshots to |
| config\_topic\_arn | ARN of the SNS topic AWS Config delivers notifications to |
| configuration\_recorder\_name | Name of the AWS Config configuration recorder |
<!-- END_TF_DOCS -->
