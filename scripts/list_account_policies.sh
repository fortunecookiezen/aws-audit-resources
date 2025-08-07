#!/usr/bin/env bash

# List all accounts in the organization
aws organizations list-accounts --query 'Accounts[*].[Id, Name]' --output text | while read account_id account_name; do
    echo "Account ID: $account_id, Name: $account_name"
    
    # List Service Control Policies (SCPs) attached to the account
    echo "  Attached Service Control Policies:"
    aws organizations list-policies-for-target --target-id "$account_id" --filter SERVICE_CONTROL_POLICY --query 'Policies[*].[Name]' --output text
done
