output "config_bucket_name" {
  description = "Name of the S3 bucket AWS Config delivers configuration history and snapshots to"
  value       = aws_s3_bucket.config.id
}

output "config_topic_arn" {
  description = "ARN of the SNS topic AWS Config delivers notifications to"
  value       = local.create_topic ? aws_sns_topic.config[0].arn : var.sns_topic_arn
}

output "configuration_recorder_name" {
  description = "Name of the AWS Config configuration recorder"
  value       = aws_config_configuration_recorder.this.name
}
