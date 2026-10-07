output "remote_admin_assume_role_group_arn" {
  description = "Assume Remote Admin Role Group ARN"
  value       = aws_iam_group.this.arn
}

output "remote_admin_assume_role_group_name" {
  description = "Assume Remote Admin Role Group Name"
  value       = aws_iam_group.this.name
}
