# Usefule Scripts

## aws organizations commands

### List all active accounts in an organization

```bash
aws organizations list-accounts --query 'Accounts[?Status==`ACTIVE`].[Name, Id, Email]' --output table
```
