# Terraform modules for security and audit functions in an AWS account

These modules create the same resources as the [CloudFormation templates](../cloudformation/README.md), for teams that prefer Terraform. Each directory is a standalone module: you can run it directly, or call it from your own configuration.

| Module | CloudFormation equivalent | Apply in |
| ------ | ------------------------- | -------- |
| [`security-audit-role`](security-audit-role/) | `security-audit-role.yml` | Each target/member account, once (IAM is global) |
| [`security-support-role`](security-support-role/) | `security-support-role.yml` | Each target/member account, once (IAM is global) |
| [`access-analyzer`](access-analyzer/) | `create_account_access_analyzer.yml` | The management or Access Analyzer delegated administrator account, in every region you use |
| [`aws-config`](aws-config/) | `EnableAWSConfig.yml` | Each account, in every region you want recorded |
| [`assume-role`](assume-role/) | `assume-role.yml` | The account holding the IAM users who switch roles |

Each module's README has its inputs, outputs, and an example. The modules are separate because they are applied in different accounts and regions. Putting them in one configuration would apply them all to a single account and region.

## Requirements

- Terraform >= 1.5.0 (OpenTofu should also work, but these modules are only tested with Terraform)
- [hashicorp/aws](https://registry.terraform.io/providers/hashicorp/aws/latest) provider >= 6.0
- AWS credentials for the account (and region) you're applying to

## What these modules don't decide for you

**State backend.** No module declares a `backend`, so Terraform uses local state (a `terraform.tfstate` file in the directory you run it from) unless you configure one. Where and how you keep state is up to you. See [Configuring a state backend](#configuring-a-state-backend).

**Provider configuration.** No module declares a `provider "aws"` block. The provider uses the standard AWS credential and region settings: `AWS_PROFILE`, `AWS_REGION`, environment credentials, IAM Identity Center sessions, and so on. When you call a module from your own configuration, it inherits your provider, or the one you pass with `providers = { ... }`.

**Tags.** No tags are applied by default. Every module that creates taggable resources has a `tags` input (default `{}`). You can also set `default_tags` on your own provider block.

## Usage

### Option 1: call the modules from your own configuration (recommended)

Reference a module by its Git path from your existing Terraform configuration. Your configuration supplies the backend, provider, and account/region targeting, so nothing in this repo needs to change. Pin `ref` to a tag or commit so upstream changes don't reach you unannounced.

```hcl
provider "aws" {
  region = "us-east-1"

  assume_role {
    role_arn = "arn:aws:iam::222222222222:role/YourDeploymentRole"
  }
}

module "security_audit_role" {
  source = "github.com/fortunecookiezen/aws-audit-resources//terraform/security-audit-role?ref=<tag-or-commit>"

  principal_account_id          = "111111111111"
  trusted_principal_arn_pattern = "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_SecurityAudit_*"
}
```

### Option 2: run a module directly

Clone the repo, change into a module directory, and supply inputs in a `terraform.tfvars` file. This repo's `.gitignore` already ignores `*.tfvars` files, so they won't be committed.

```bash
cd terraform/security-audit-role

cat > terraform.tfvars <<'EOF'
principal_account_id          = "111111111111"
trusted_principal_arn_pattern = "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_SecurityAudit_*"
EOF

export AWS_PROFILE=target-account-admin   # credentials for the account you're deploying into
terraform init
terraform plan
terraform apply
```

Without a backend, state is written to `terraform.tfstate` in the module directory. That file is gitignored too, but it's the only record of what Terraform created, so keep it somewhere safe or configure a backend.

## Configuring a state backend

How you do this depends on how you use the modules:

- **Calling the modules from your own configuration (option 1):** declare the backend in your configuration as you normally would. The modules don't need to change.
- **Running a module directly (option 2):** add a file named `backend_override.tf` to the module directory. Terraform merges `*_override.tf` files into the configuration, and this repo's `.gitignore` already excludes them, so your backend settings stay out of version control. For example, with S3:

  ```hcl
  # terraform/security-audit-role/backend_override.tf
  terraform {
    backend "s3" {
      bucket       = "your-terraform-state-bucket"
      key          = "aws-audit-resources/222222222222/security-audit-role.tfstate"
      region       = "us-east-1"
      use_lockfile = true
    }
  }
  ```

  Then run `terraform init`. If you already applied with local state, run `terraform init -migrate-state` to move it.

Use a separate state file (a different `key`, workspace, or directory) for each account and region you apply a module in.

## Applying in several regions

`access-analyzer` and `aws-config` are regional. To cover several regions from one configuration, define a provider alias per region and call the module once for each:

```hcl
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

provider "aws" {
  alias  = "us_west_2"
  region = "us-west-2"
}

module "access_analyzer_us_east_1" {
  source    = "github.com/fortunecookiezen/aws-audit-resources//terraform/access-analyzer?ref=<tag-or-commit>"
  providers = { aws = aws.us_east_1 }

  # Paid feature: enable the unused access analyzer in one region only. See the module README.
  enable_unused_access_analyzer = false
}

module "access_analyzer_us_west_2" {
  source    = "github.com/fortunecookiezen/aws-audit-resources//terraform/access-analyzer?ref=<tag-or-commit>"
  providers = { aws = aws.us_west_2 }
}
```

For `aws-config`, also set `service_linked_role_region` to one of the regions so the (global) Config service-linked role is only created once.

## Development

Validate and lint every module:

```bash
for d in terraform/*/; do
  (cd "$d" && terraform init -backend=false -input=false >/dev/null && terraform validate) || echo "FAILED: $d"
done
terraform fmt -recursive -check terraform
for d in terraform/*/; do tflint --chdir="$d"; done
```

The inputs/outputs tables in each module README are generated with [terraform-docs](https://terraform-docs.io/). After changing a module's variables or outputs, regenerate them:

```bash
for d in terraform/*/; do terraform-docs -c terraform/.terraform-docs.yml "$d"; done
```

`terraform init` creates a `.terraform.lock.hcl` file in each module directory. The lock files aren't committed, so each user chooses their own provider version within the `>= 6.0` constraint. If you run the modules directly, commit the lock file in your own copy to keep provider versions consistent.
