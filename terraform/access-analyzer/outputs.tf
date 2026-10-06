output "organization_access_analyzer_arn" {
  description = "Organization Access Analyzer ARN"
  value       = aws_accessanalyzer_analyzer.organization.arn
}

output "organization_unused_access_analyzer_arn" {
  description = "Organization Unused Access Analyzer ARN, or null if enable_unused_access_analyzer is false"
  value       = one(aws_accessanalyzer_analyzer.organization_unused_access[*].arn)
}
