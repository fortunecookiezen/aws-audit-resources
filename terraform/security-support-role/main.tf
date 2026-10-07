data "aws_partition" "current" {}

data "aws_caller_identity" "current" {}

locals {
  partition  = data.aws_partition.current.partition
  account_id = data.aws_caller_identity.current.account_id

  managed_policy_arns = toset([
    "arn:${local.partition}:iam::aws:policy/AmazonInspector2ReadOnlyAccess",
    "arn:${local.partition}:iam::aws:policy/AWSSecurityHubReadOnlyAccess",
    "arn:${local.partition}:iam::aws:policy/AWSSupportAccess",
    "arn:${local.partition}:iam::aws:policy/ReadOnlyAccess",
    "arn:${local.partition}:iam::aws:policy/SecurityAudit",
  ])

  iam_quarantine_policy_arn = coalesce(
    var.iam_quarantine_policy_arn,
    "arn:${local.partition}:iam::aws:policy/AWSCompromisedKeyQuarantineV3",
  )

  iam_identity_arns = [
    "arn:${local.partition}:iam::${local.account_id}:user/*",
    "arn:${local.partition}:iam::${local.account_id}:role/*",
  ]
}

data "aws_iam_policy_document" "trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    # Trusting "*" is done to allow the use of SSO in principal_account_id. By using the wildcard and the
    # condition keys, you are trusting only the specific principal(s) matching
    # trusted_principal_arn_pattern within principal_account_id - narrower than trusting the whole account
    # root, since SSO permission set role ARNs contain a generated path segment that can't be referenced
    # directly as a principal.
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalAccount"
      values   = [var.principal_account_id]
    }

    condition {
      test     = "StringLike"
      variable = "aws:PrincipalArn"
      values   = [var.trusted_principal_arn_pattern]
    }

    dynamic "condition" {
      for_each = var.require_mfa ? [1] : []
      content {
        test     = "Bool"
        variable = "aws:MultiFactorAuthPresent"
        values   = ["true"]
      }
    }
  }
}

resource "aws_iam_role" "this" {
  name                 = "${var.org_prefix}-CrossAccountSecuritySupportRole"
  description          = "Cross-account security incident-response support role"
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = var.max_session_duration_seconds
  tags                 = var.tags
}

resource "aws_iam_role_policy_attachment" "managed" {
  for_each = local.managed_policy_arns

  role       = aws_iam_role.this.name
  policy_arn = each.value
}

data "aws_iam_policy_document" "incident_response_containment" {
  statement {
    sid = "IAMCredentialContainment"
    actions = [
      "iam:UpdateAccessKey",
      "iam:DeleteLoginProfile",
      "iam:TagUser",
      "iam:TagRole",
    ]
    resources = local.iam_identity_arns
  }

  # The iam:PolicyARN condition locks attachment to exactly one quarantine policy, so this grant can't be
  # used to attach AdministratorAccess or anything else.
  statement {
    sid = "IAMQuarantineAttach"
    actions = [
      "iam:AttachUserPolicy",
      "iam:AttachRolePolicy",
    ]
    resources = local.iam_identity_arns

    condition {
      test     = "StringEquals"
      variable = "iam:PolicyARN"
      values   = [local.iam_quarantine_policy_arn]
    }
  }

  statement {
    sid = "Ec2NetworkIsolation"
    actions = [
      "ec2:CreateSecurityGroup",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:ModifyInstanceAttribute",
      "ec2:ModifyNetworkInterfaceAttribute",
      "ec2:CreateSnapshot",
      "ec2:CreateImage",
      "ec2:CreateTags",
    ]
    resources = ["*"]
  }

  statement {
    sid = "S3ExposureLockdown"
    actions = [
      "s3:PutBucketPublicAccessBlock",
      "s3:PutBucketAcl",
    ]
    resources = ["*"]
  }

  statement {
    sid = "LoggingControlRestoration"
    actions = [
      "cloudtrail:StartLogging",
      "cloudtrail:PutEventSelectors",
      "config:StartConfigurationRecorder",
      "guardduty:UpdateDetector",
    ]
    resources = ["*"]
  }

  statement {
    sid = "FindingWorkflowUpdates"
    actions = [
      "securityhub:BatchUpdateFindings",
      "securityhub:UpdateFindings",
      "guardduty:ArchiveFindings",
      "guardduty:UnarchiveFindings",
      "guardduty:UpdateFindingsFeedback",
    ]
    resources = ["*"]
  }

  statement {
    sid = "LambdaSecretsContainment"
    actions = [
      "lambda:PutFunctionConcurrency",
      "lambda:DeleteFunctionConcurrency",
      "lambda:UpdateEventSourceMapping",
      "secretsmanager:RotateSecret",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "incident_response_containment" {
  name   = "IncidentResponseContainment"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.incident_response_containment.json
}
