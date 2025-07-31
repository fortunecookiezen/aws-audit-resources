# Usefule Scripts

## aws organizations
```bash
aws organizations list-accounts --query 'Accounts[?Status==`ACTIVE`].[Name, Id, Email]' --output table
```
