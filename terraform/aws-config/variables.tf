variable "all_supported" {
  description = "Indicates whether to record all supported resource types."
  type        = bool
  default     = true
}

variable "include_global_resource_types" {
  description = "Indicates whether AWS Config records all supported global resource types."
  type        = bool
  default     = false
}

variable "resource_types" {
  description = <<-EOT
    A list of valid AWS resource types to include in this recording group, such as AWS::EC2::Instance or
    AWS::CloudTrail::Trail. Ignored when all_supported is true.
  EOT
  type        = list(string)
  default     = []

  validation {
    condition     = var.all_supported || length(var.resource_types) > 0
    error_message = "resource_types must list at least one resource type when all_supported is false."
  }
}

variable "recording_frequency" {
  description = "The frequency with which the AWS Config recorder records configuration changes: CONTINUOUS or DAILY."
  type        = string

  validation {
    condition     = contains(["CONTINUOUS", "DAILY"], var.recording_frequency)
    error_message = "recording_frequency must be CONTINUOUS or DAILY."
  }
}

variable "delivery_channel_name" {
  description = "The name of the delivery channel. Uses the provider default (\"default\") when null."
  type        = string
  default     = null
}

variable "snapshot_delivery_frequency" {
  description = "The frequency with which AWS Config delivers configuration snapshots."
  type        = string
  default     = "TwentyFour_Hours"

  validation {
    condition     = contains(["One_Hour", "Three_Hours", "Six_Hours", "Twelve_Hours", "TwentyFour_Hours"], var.snapshot_delivery_frequency)
    error_message = "snapshot_delivery_frequency must be one of One_Hour, Three_Hours, Six_Hours, Twelve_Hours, TwentyFour_Hours."
  }
}

variable "sns_topic_arn" {
  description = "ARN of an existing SNS topic that AWS Config delivers notifications to. A new topic is created when null."
  type        = string
  default     = null
}

variable "notification_email" {
  description = "Email address subscribed to AWS Config notifications. Only used when a new topic is created (sns_topic_arn is null)."
  type        = string
  default     = null
}

variable "service_linked_role_region" {
  description = <<-EOT
    A region such as us-east-1. If set, the Config service-linked role is only created when this module is
    applied in that region, so deploying to several regions doesn't try to create the (global) role twice.
    When null, the role is created in whatever region the module is applied in.
  EOT
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags to apply to the S3 bucket, SNS topic, and service-linked role. None are applied by default."
  type        = map(string)
  default     = {}
}
