data "aws_partition" "current" {}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

locals {
  partition  = data.aws_partition.current.partition
  account_id = data.aws_caller_identity.current.account_id

  create_topic        = var.sns_topic_arn == null
  create_subscription = local.create_topic && var.notification_email != null
  create_config_slr   = var.service_linked_role_region == null || var.service_linked_role_region == data.aws_region.current.region
}

# The bucket holds the recorded configuration history, so it is protected from deletion and replacement.
# To tear this module down while keeping the bucket, remove it from state first, e.g.
# terraform state rm aws_s3_bucket.config aws_s3_bucket_server_side_encryption_configuration.config aws_s3_bucket_policy.config
resource "aws_s3_bucket" "config" {
  bucket_prefix = "config-bucket-"
  tags          = var.tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

data "aws_iam_policy_document" "config_bucket" {
  statement {
    sid       = "AWSConfigBucketPermissionsCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.config.arn]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "AWSConfigBucketDelivery"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config.arn}/AWSLogs/${local.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid     = "AWSConfigBucketSecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.config.arn,
      "${aws_s3_bucket.config.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "config" {
  bucket = aws_s3_bucket.config.id
  policy = data.aws_iam_policy_document.config_bucket.json
}

resource "aws_sns_topic" "config" {
  count = local.create_topic ? 1 : 0

  name              = "config-topic-${local.account_id}"
  display_name      = "AWS Config Notification Topic"
  kms_master_key_id = "alias/aws/sns"
  tags              = var.tags
}

data "aws_iam_policy_document" "config_topic" {
  count = local.create_topic ? 1 : 0

  statement {
    sid       = "AWSConfigSNSPolicy"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.config[0].arn]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_sns_topic_policy" "config" {
  count = local.create_topic ? 1 : 0

  arn    = aws_sns_topic.config[0].arn
  policy = data.aws_iam_policy_document.config_topic[0].json
}

resource "aws_sns_topic_subscription" "email" {
  count = local.create_subscription ? 1 : 0

  topic_arn = aws_sns_topic.config[0].arn
  protocol  = "email"
  endpoint  = var.notification_email
}

resource "aws_iam_service_linked_role" "config" {
  count = local.create_config_slr ? 1 : 0

  aws_service_name = "config.amazonaws.com"
  tags             = var.tags
}

resource "aws_config_configuration_recorder" "this" {
  role_arn = "arn:${local.partition}:iam::${local.account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"

  recording_group {
    all_supported                 = var.all_supported
    include_global_resource_types = var.include_global_resource_types
    resource_types                = var.all_supported ? null : var.resource_types
  }

  recording_mode {
    recording_frequency = var.recording_frequency
  }

  depends_on = [
    aws_s3_bucket_policy.config,
    aws_iam_service_linked_role.config,
  ]
}

resource "aws_config_delivery_channel" "this" {
  name           = var.delivery_channel_name
  s3_bucket_name = aws_s3_bucket.config.id
  sns_topic_arn  = local.create_topic ? aws_sns_topic.config[0].arn : var.sns_topic_arn

  snapshot_delivery_properties {
    delivery_frequency = var.snapshot_delivery_frequency
  }

  depends_on = [
    aws_s3_bucket_policy.config,
    aws_config_configuration_recorder.this,
  ]
}

# CloudFormation starts the recorder implicitly; Terraform needs an explicit status resource.
resource "aws_config_configuration_recorder_status" "this" {
  name       = aws_config_configuration_recorder.this.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.this]
}
