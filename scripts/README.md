# Useful Commands and scripts for conducting an audit of aws accounts
## aws iam

### assume remote role for auditing purposes

Before assuming the remote role _remember to export AUDIT_ROLE_ARN_

```bash
eval $(aws sts assume-role --role-arn $AUDIT_ROLE_ARN \
--role-session-name audit-session | jq -r '.Credentials | "export AWS_ACCESS_KEY_ID=\(.AccessKeyId)\nexport AWS_SECRET_ACCESS_KEY=\(.SecretAccessKey)\nexport AWS_SESSION_TOKEN=\(.SessionToken)\n"')
```

## aws organizations

### List all active accounts in an organization

```bash
aws organizations list-accounts --query 'Accounts[?Status==`ACTIVE`].[Name, Id, Email]' --output table
```
