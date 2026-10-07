resource "aws_accessanalyzer_analyzer" "organization" {
  analyzer_name = var.analyzer_name
  type          = "ORGANIZATION"
  tags          = var.tags
}

resource "aws_accessanalyzer_analyzer" "organization_unused_access" {
  count = var.enable_unused_access_analyzer ? 1 : 0

  analyzer_name = var.unused_access_analyzer_name
  type          = "ORGANIZATION_UNUSED_ACCESS"
  tags          = var.tags

  configuration {
    unused_access {
      unused_access_age = var.unused_access_age_days
    }
  }
}
