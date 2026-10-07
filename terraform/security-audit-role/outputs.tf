output "security_audit_role_arn" {
  description = "CrossAccountSecurityAuditRole role ARN"
  value       = aws_iam_role.this.arn
}
