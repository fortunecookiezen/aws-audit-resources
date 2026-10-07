data "aws_region" "current" {}

resource "aws_iam_group" "this" {
  name = "${var.group_name}-${data.aws_region.current.region}"
}

data "aws_iam_policy_document" "cross_account_access" {
  statement {
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = var.target_account_role_arns
  }
}

resource "aws_iam_group_policy" "cross_account_access" {
  name   = "CrossAccountAccessPolicy"
  group  = aws_iam_group.this.name
  policy = data.aws_iam_policy_document.cross_account_access.json
}
