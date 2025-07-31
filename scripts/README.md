# Useful Commands and scripts for conducting an audit of aws accounts

## aws organizations

### List all active accounts in an organization

```bash
aws organizations list-accounts --query 'Accounts[?Status==`ACTIVE`].[Name, Id, Email]' --output table
```
