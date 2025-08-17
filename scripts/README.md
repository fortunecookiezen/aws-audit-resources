# Useful Commands and scripts for conducting an audit of aws accounts

Most, if not all of this is designed to be run from AWS CloudShell sessions

## Authentication

### assume remote role for auditing purposes

Before assuming the remote role _remember to export AUDIT_ROLE_ARN_

```bash
eval $(aws sts assume-role --role-arn $AUDIT_ROLE_ARN \
--role-session-name audit-session | jq -r '.Credentials | "export AWS_ACCESS_KEY_ID=\(.AccessKeyId)\nexport AWS_SECRET_ACCESS_KEY=\(.SecretAccessKey)\nexport AWS_SESSION_TOKEN=\(.SessionToken)\n"')
```

## aws cloudwatch

### Describe CloudWatch alarms

```bash
aws cloudwatch describe-alarms
```

```bash
aws cloudwatch describe-alarms-for-metric --metric-name CPUUtilization --namespace AWS/EC2 --dimensions Name=InstanceId,Value=i-1234567890abcdef0
```

## aws EC2 Security Groups

### Generate Instances Report

```bash
echo "\"InstanceId\",\"KeyName\",\"InstanceProfile\",\"SubnetId\",\"NetworkInterfaceId\",\"VpcId\",\"PublicIp\",\"PublicDnsName\",\"SecurityGroupId\",\"SecurityGroupName\",\"PrivateIpAddress\",\"PrivateDnsName\""
aws ec2 describe-instances | jq -r '.Reservations[].Instances[] | [.InstanceId,.KeyName,.IamInstanceProfile.Arn,.NetworkInterfaces[].NetworkInterfaceId,.NetworkInterfaces[].SubnetId,.NetworkInterfaces[].VpcId,.NetworkInterfaces[].Association.PublicIp,.NetworkInterfaces[].Association.PublicDnsName,.SecurityGroups[].GroupId,.SecurityGroups[].GroupName,.NetworkInterfaces[].PrivateIpAddress,.NetworkInterfaces[].PrivateDnsName] | @csv'
```

### Port 22

```bash
aws ec2 describe-security-groups \
--filters "Name=ip-permission.protocol,Values=tcp" \
"Name=ip-permission.from-port,Values=22" \
"Name=ip-permission.to-port,Values=22" \
"Name=ip-permission.cidr,Values=0.0.0.0/0" \
--query "SecurityGroups[*].[GroupId,GroupName]" --output table
```

### Port 80

```bash
aws ec2 describe-security-groups \
--filters "Name=ip-permission.protocol,Values=tcp" \
"Name=ip-permission.from-port,Values=80" \
"Name=ip-permission.to-port,Values=80" \
"Name=ip-permission.cidr,Values=0.0.0.0/0" \
--query "SecurityGroups[*].[GroupId,GroupName]" --output table
```

### Port 443

```bash
aws ec2 describe-security-groups \
--filters "Name=ip-permission.protocol,Values=tcp" \
"Name=ip-permission.from-port,Values=443" \
"Name=ip-permission.to-port,Values=443" \
"Name=ip-permission.cidr,Values=0.0.0.0/0" \
--query "SecurityGroups[*].[GroupId,GroupName]" | jq -r '.[] | @csv'
```

```bash
aws ec2 describe-security-groups \
--filters "Name=ip-permission.protocol,Values=tcp" \
"Name=ip-permission.from-port,Values=3389" \
"Name=ip-permission.to-port,Values=3389" \
"Name=ip-permission.cidr,Values=0.0.0.0/0" \
--query "SecurityGroups[*].[GroupId,GroupName]" | jq -r '.[] | @csv'
```

### Open Internet Security Groups

```bash
aws ec2 describe-security-groups \
--filters "Name=ip-permission.protocol,Values=tcp" "Name=ip-permission.cidr,Values=0.0.0.0/0" --query "SecurityGroups[*]" | jq -r '.[] | [.GroupId, .GroupName, .IpPermissions[].IpRanges[].CidrIp, .IpPermissions[].ToPort] | @csv'
```

```bash
aws ec2 describe-network-interfaces --filters "Name=group-id,Values=$security_group_id" --query 'NetworkInterfaces[*].[NetworkInterfaceId, SubnetId, PrivateIpAddress, Description]' --output table
```

## aws GuardDuty; service principal`guardduty.amazonaws.com`

### Verify GuardDuty is enabled in a single region

```bash
    aws guardduty list-detectors --region $AWS_REGION --query "DetectorIds[0]"
```

### Verify GuardDuty is enabled in all regions

```bash
    for region in $(aws ec2 describe-regions --all-regions --query "Regions[].RegionName" --output text); do
      echo "Checking GuardDuty in region: $region"
      detector_id=$(aws guardduty list-detectors --region "$region" --query "DetectorIds[0]" --output text 2>/dev/null)
      if [ -z "$detector_id" ]; then
        echo "  GuardDuty is NOT enabled in $region." 
      else
        echo "  GuardDuty is ENABLED in $region (Detector ID: $detector_id)."
      fi
    done
```

```bash
aws guardduty get-coverage-statistics --detector-id=$(aws guardduty list-detectors --region $AWS_REGION --query "DetectorIds[0]" --output text) --statistics-type=COUNT_BY_COVERAGE_STATUS
```

```bash
aws guardduty get-coverage-statistics --detector-id=$(aws guardduty list-detectors --region $AWS_REGION --query "DetectorIds[0]" --output text) --statistics-type=COUNT_BY_RESOURCE_TYPE
```

```bash
aws guardduty get-organization-statistics
```

### list GuardDuty findings

```bash
aws guardduty list-findings \
    --detector-id $(aws guardduty list-detectors --region $AWS_REGION --query "DetectorIds[0]" --output text) \
    --sort-criteria '{"AttributeName": "updatedAt", "OrderBy": "DESC"}' \
    --query 'FindingIds'. --output text
```

```bash
aws guardduty get-findings \
--detector-id $(aws guardduty list-detectors --region $AWS_REGION --query "DetectorIds[0]" --output text) --finding-id 32cc0d10b98943ec7a49f8abf77baee2 \
--query "Findings[].Description" --output text
```

## aws IAM

## get account details

```bash
aws iam get-account-password-policy --output table
```

```bash
aws iam get-account-summary --output table
```

### download all local iam users and create a csv with _userName, Arn, PasswordLastUsed_

```bash
aws iam list-users | jq -r '.Users[] | [.UserName, .Arn, .PasswordLastUsed] | @csv'
```

### install [iam-collect](https://github.com/cloud-copilot/iam-collect) and [iam-lens](https://github.com/cloud-copilot/iam-lens) and download iam policies from account

```bash
npm install -g @cloud-copilot/iam-collect @cloud-copilot/iam-lens --prefix .
iam-collect init
iam-collect download --region YOUR_REGION_HERE
```

### generate credential report

```bash
aws iam generate-credential-report
```

```bash
aws iam get-credential-report --query 'Content' --output text | base64 --decode > credential_report.csv
```

```bash
aws accessanalyzer list-analyzers --query "analyzers[*].[arn,name]" --output table
```

```bash
aws accessanalyzer list-findings --analyzer-arn $(aws accessanalyzer list-analyzers --query "analyzers[*].[arn]" --output text) --query "findings[*].[resource,resourceType]" --output table
```

## aws organizations

### List all active accounts in an organization and output a table with the results

```bash
aws organizations list-accounts --query 'Accounts[?Status==`ACTIVE`].[Name, Id, Email]' --output table
```

### List all active accounts in an organization and output a csv file with the results

```bash
aws organizations list-accounts \
--query 'Accounts[?Status==`ACTIVE`]' | jq -r '.[] | [.Id, .Name, .Email] | @csv'
```

### Verify technical and security contacts exist

## aws Secretsmanager

List secret names and arns

```bash
aws secretsmanager list-secrets --query "SecretList[].[Name, ARN]" | jq -r '.[] | @csv'
```

## aws Shield

```bash
aws shield describe-subscription
```

## aws Support

### verify support plan is in place

Confirm Support is one of:

* Business
* Enterprise On-Ramp
* Enterprise
