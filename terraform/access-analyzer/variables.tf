variable "analyzer_name" {
  description = "Name of the external access analyzer."
  type        = string
  default     = "OrganizationAccessAnalyzer"
}

variable "enable_unused_access_analyzer" {
  description = <<-EOT
    Also create an unused access analyzer, which reports unused IAM roles, unused IAM user access keys and
    passwords, and unused permissions across every account in the organization. WARNING: this is a PAID
    feature, billed monthly per IAM role and IAM user analyzed across all member accounts, for each unused
    access analyzer you create. Estimate the cost before enabling it
    (https://aws.amazon.com/iam/access-analyzer/pricing/). IAM is global, so enable this in only one region -
    enabling it in every region where you deploy this module multiplies the charge for no additional findings.
  EOT
  type        = bool
  default     = false
}

variable "unused_access_analyzer_name" {
  description = "Name of the unused access analyzer. Ignored unless enable_unused_access_analyzer is true."
  type        = string
  default     = "OrganizationUnusedAccessAnalyzer"
}

variable "unused_access_age_days" {
  description = <<-EOT
    Number of days without use after which a role, credential, or permission is reported as unused.
    Ignored unless enable_unused_access_analyzer is true.
  EOT
  type        = number
  default     = 90

  validation {
    condition     = var.unused_access_age_days >= 1 && var.unused_access_age_days <= 365
    error_message = "unused_access_age_days must be between 1 and 365."
  }
}

variable "tags" {
  description = "Tags to apply to the analyzers. None are applied by default."
  type        = map(string)
  default     = {}
}
