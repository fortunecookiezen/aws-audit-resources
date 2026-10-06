variable "group_name" {
  description = "Name for the group. The current region is appended, e.g. {group_name}-us-east-1."
  type        = string
}

variable "target_account_role_arns" {
  description = "List of IAM role ARNs in other accounts that members of the group may assume."
  type        = list(string)

  validation {
    condition     = length(var.target_account_role_arns) > 0 && alltrue([for arn in var.target_account_role_arns : can(regex("^arn:[^:]+:iam::\\d{12}:role/.+$", arn))])
    error_message = "target_account_role_arns must contain at least one IAM role ARN, e.g. arn:aws:iam::123456789012:role/ROLE_NAME."
  }
}
