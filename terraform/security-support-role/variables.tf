variable "org_prefix" {
  description = "Organizational prefix for resources. The role is named {org_prefix}-CrossAccountSecuritySupportRole."
  type        = string
  default     = "opspath"

  validation {
    condition     = can(regex("^[a-z]*$", var.org_prefix))
    error_message = "org_prefix must contain only lower-case letters."
  }
}

variable "principal_account_id" {
  description = "12 digit id of the account containing the users to which you're granting access."
  type        = string

  validation {
    condition     = can(regex("^\\d{12}$", var.principal_account_id))
    error_message = "principal_account_id must be a 12 digit AWS account id."
  }
}

variable "trusted_principal_arn_pattern" {
  description = <<-EOT
    IAM principal ARN pattern (matched with a StringLike condition) within principal_account_id that is
    allowed to assume this role. Scope this to the specific SSO permission set or role you use for
    incident-response work, rather than trusting every IAM principal in the account, e.g.
    `arn:aws:iam::{principal_account_id}:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_YourPermissionSetName_*`
    Pass `"*"` only if you intentionally want to trust every IAM principal in principal_account_id.
  EOT
  type        = string
}

variable "require_mfa" {
  description = <<-EOT
    Require aws:MultiFactorAuthPresent on the calling session to assume this role. Must be false if your
    workforce users access AWS through AWS IAM Identity Center: Identity Center sessions never carry
    aws:MultiFactorAuthPresent (enforce MFA at Identity Center sign-in instead), so true locks every SSO
    user out of the role. Only set to true for IAM users or federated principals whose sessions are issued
    with MFA context (e.g. sts:GetSessionToken with an MFA device).
  EOT
  type        = bool
  default     = false
}

variable "max_session_duration_seconds" {
  description = "Maximum session duration, in seconds, for role sessions. Must be between 3600 (1 hour) and 43200 (12 hours)."
  type        = number
  default     = 3600

  validation {
    condition     = var.max_session_duration_seconds >= 3600 && var.max_session_duration_seconds <= 43200
    error_message = "max_session_duration_seconds must be between 3600 and 43200."
  }
}

variable "iam_quarantine_policy_arn" {
  description = <<-EOT
    Managed policy this role is permitted to attach to a suspected-compromised IAM user or role in order to
    contain it. Defaults (when null) to the AWS-maintained AWSCompromisedKeyQuarantineV3 policy, which denies
    privilege-escalation and abuse-enabling actions (attaching/creating policies, creating access keys,
    PassRole, RunInstances, CreateBucket, etc.) without removing the identity or its existing access for
    forensic review. Override only if your organization maintains its own quarantine policy.
  EOT
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags to apply to the role. None are applied by default."
  type        = map(string)
  default     = {}
}
