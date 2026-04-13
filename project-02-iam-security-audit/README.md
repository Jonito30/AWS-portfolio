# Project 02 - IAM Security Audit Script

## What I Built
A Python script that connects to AWS and audits IAM security settings, flagging potential risks.

## AWS Services Used
- **IAM** — Identity and Access Management
- **Boto3** — AWS Python SDK
- **AWS CLI** — configured locally to authenticate the script

## What the Script Checks
- Lists all IAM users in the account
- Detects users with no MFA enabled
- Flags access keys older than 90 days
- Detects AdministratorAccess via direct policies AND group memberships

## What I Learned
- How IAM users, groups, and policies work
- How to install and configure the AWS CLI
- How to use Boto3 to query AWS programmatically
- Real security best practices for AWS accounts

## Findings on My Account
- Johnny has no MFA enabled ⚠️
- Johnny has AdministratorAccess via group 'admin' ⚠️
- Access key is 0 days old ✅