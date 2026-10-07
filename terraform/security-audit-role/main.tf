data "aws_partition" "current" {}

locals {
  managed_policy_arns = toset([
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonInspector2ReadOnlyAccess",
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/AWSSecurityHubReadOnlyAccess",
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/SecurityAudit",
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/job-function/ViewOnlyAccess",
  ])
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
  name                 = "${var.org_prefix}-CrossAccountSecurityAuditRole"
  description          = "Cross-account read-only security audit role"
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = var.max_session_duration_seconds
  tags                 = var.tags
}

resource "aws_iam_role_policy_attachment" "managed" {
  for_each = local.managed_policy_arns

  role       = aws_iam_role.this.name
  policy_arn = each.value
}

data "aws_iam_policy_document" "supplemental_read_only" {
  statement {
    sid = "NotificationsReadOnly"
    actions = [
      "notifications-contacts:GetEmailContact",
      "notifications-contacts:ListEmailContacts",
      "notifications-contacts:ListTagsForResource",
      "notifications:GetEventRule",
      "notifications:GetNotificationConfiguration",
      "notifications:GetNotificationEvent",
      "notifications:ListChannels",
      "notifications:ListEventRules",
      "notifications:ListNotificationConfigurations",
      "notifications:ListNotificationEvents",
      "notifications:ListNotificationHubs",
      "notifications:ListTagsForResource",
    ]
    resources = ["*"]
  }

  statement {
    sid = "AllowAccessAnalyzerView"
    actions = [
      "access-analyzer:CheckAccessNotGranted",
      "access-analyzer:CheckNoNewAccess",
      "access-analyzer:GetAccessPreview",
      "access-analyzer:GetAnalyzedResource",
      "access-analyzer:GetAnalyzer",
      "access-analyzer:GetArchiveRule",
      "access-analyzer:GetFinding",
      "access-analyzer:GetFindingsStatistics",
      "access-analyzer:GetGeneratedPolicy",
      "access-analyzer:ListAccessPreviewFindings",
      "access-analyzer:ListAccessPreviews",
      "access-analyzer:ListAnalyzedResources",
      "access-analyzer:ListAnalyzers",
      "access-analyzer:ListArchiveRules",
      "access-analyzer:ListFindings",
      "access-analyzer:ListPolicyGenerations",
      "access-analyzer:ListTagsForResource",
      "access-analyzer:ValidatePolicy",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "ServiceDiscovery"
    actions   = ["servicediscovery:ListNamespaces"]
    resources = ["*"]
  }

  statement {
    sid = "DescribeSecurityServices"
    actions = [
      "account:ListRegions",
      "apigateway:GET",
      "dlm:GetLifecyclePolicies",
      "dlm:GetLifecyclePolicy",
      "dlm:ListTagsForResource",
      "dynamodb:GetResourcePolicy",
      "ecr:Describe*",
      "guardduty:Describe*",
      "guardduty:Get*",
      "guardduty:List*",
      "macie2:Describe*",
      "macie2:Get*",
      "macie2:List*",
      "s3:GetStorageLensConfiguration",
      "s3:GetStorageLensDashboard",
      "shield:Describe*",
      "shield:Get*",
      "shield:List*",
      "wafv2:Describe*",
      "wafv2:Get*",
      "wafv2:List*",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "CloudTrail"
    actions   = ["cloudtrail:ListEventDataStores"]
    resources = ["*"]
  }

  statement {
    sid       = "STSCallerIdentity"
    actions   = ["sts:GetCallerIdentity"]
    resources = ["*"]
  }

  # organizations:DescribeOrganization works from any member account (org id,
  # management account id, feature set) - used to give the report context even
  # when the next permission can't be exercised.
  # iam:ListOrganizationsFeatures only succeeds from the Organizations
  # management account or an account delegated as IAM's trusted administrator;
  # from a plain member account it fails with
  # AccountNotManagementOrDelegatedAdministrator, which collect_aws_data.py
  # treats as expected, not an error. When it does succeed, it tells
  # run_checks.py whether root credentials are centrally managed via AWS
  # Organizations, so root_mfa_enabled/root_hardware_mfa/root_not_used_routinely
  # aren't flagged as false positives for an account whose root credentials were
  # deliberately deleted org-wide rather than just left unsecured. See
  # skill/references/exceptions-and-exclusions.md.
  # iam:ListEntitiesForPolicy lets the collector record which specific roles/users
  # hold an admin-wildcard (Action:*, Resource:*) policy, so iam_no_full_admin_policy
  # can flag the actual principal by name instead of just the policy, and a named
  # break-glass/admin role can be excepted without hiding every other attachment.
  statement {
    sid = "OrganizationsRootAccessContext"
    actions = [
      "organizations:DescribeOrganization",
      "iam:ListOrganizationsFeatures",
      "iam:ListEntitiesForPolicy",
    ]
    resources = ["*"]
  }

  statement {
    sid = "CodeStar"
    actions = [
      "codeartifact:Describe*",
      "codeartifact:GetDomainPermissionsPolicy",
      "codeartifact:GetRepositoryPermissionsPolicy",
      "codeartifact:List*",
      "codebuild:BatchGetBuilds",
      "codebuild:BatchGetProjects",
      "codebuild:BatchGetReportGroups",
      "codebuild:BatchGetReports",
      "codebuild:Describe*",
      "codebuild:List*",
      "codecommit:BatchGet*",
      "codecommit:Describe*",
      "codecommit:GetApprovalRuleTemplate",
      "codecommit:GetBranch",
      "codecommit:GetComment",
      "codecommit:GetCommentsForComparedCommit",
      "codecommit:GetCommentsForPullRequest",
      "codecommit:GetCommit",
      "codecommit:GetCommitHistory",
      "codecommit:GetDifferences",
      "codecommit:GetMergeCommit",
      "codecommit:GetMergeConflicts",
      "codecommit:GetMergeOptions",
      "codecommit:GetPullRequest*",
      "codecommit:List*",
      "codeconnections:List*",
      "codedeploy:BatchGet*",
      "codedeploy:List*",
      "codepipeline:Get*",
      "codepipeline:List*",
      "codestar:List*",
      "codestar-connections:List*",
      "codestar-notifications:List*",
    ]
    resources = ["*"]
  }

  statement {
    sid = "BillingAndAccountAudit"
    actions = [
      "account:GetAccountInformation",
      "account:GetAlternateContact",
      "account:GetContactInformation",
      "billing:Get*",
      "billing:List*",
      "ce:Describe*",
      "ce:Get*",
      "ce:List*",
      "consolidatedbilling:Get*",
      "consolidatedbilling:List*",
      "cur:Describe*",
      "cur:Get*",
      "freetier:Get*",
      "invoicing:Get*",
      "invoicing:List*",
      "payments:Get*",
      "payments:List*",
      "tax:Get*",
      "tax:List*",
    ]
    resources = ["*"]
  }

  statement {
    sid = "AIServiceAudit"
    actions = [
      "bedrock:Get*",
      "bedrock:List*",
      "bedrock-agentcore:Get*",
      "bedrock-agentcore:List*",
      "codewhisperer:Get*",
      "codewhisperer:List*",
      "qbusiness:Get*",
      "qbusiness:List*",
      "qdeveloper:List*",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "supplemental_read_only" {
  name   = "SupplementalReadOnlyAccess"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.supplemental_read_only.json
}
