import boto3
from datetime import datetime, timezone

print("=" * 50)
print("AWS IAM Security Audit")
print("=" * 50)

iam = boto3.client('iam')

# Check 1 - List all IAM users
print("\n[1] IAM USERS")
users = iam.list_users()['Users']
if not users:
    print("  No IAM users found.")
else:
    for user in users:
        print(f"  - {user['UserName']} (created: {user['CreateDate'].strftime('%Y-%m-%d')})")

# Check 2 - Check MFA status for each user
print("\n[2] MFA STATUS")
for user in users:
    mfa = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']
    status = "MFA ENABLED" if mfa else "NO MFA"
    print(f"  - {user['UserName']}: {status}")

# Check 3 - Check for old access keys
print("\n[3] ACCESS KEY AGE")
for user in users:
    keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
    if not keys:
        print(f"  - {user['UserName']}: No access keys")
    for key in keys:
        age = (datetime.now(timezone.utc) - key['CreateDate']).days
        status = "OLD - consider rotating" if age > 90 else "OK"
        print(f"  - {user['UserName']}: Key age {age} days [{status}]")

# Check 4 - Check for users with AdministratorAccess (direct + group)
print("\n[4] ADMINISTRATOR ACCESS")
for user in users:
    # Check direct policies
    direct = iam.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']
    for policy in direct:
        if policy['PolicyName'] == 'AdministratorAccess':
            print(f"  WARNING: {user['UserName']} has direct AdministratorAccess!")

    # Check group policies
    groups = iam.list_groups_for_user(UserName=user['UserName'])['Groups']
    for group in groups:
        group_policies = iam.list_attached_group_policies(GroupName=group['GroupName'])['AttachedPolicies']
        for policy in group_policies:
            if policy['PolicyName'] == 'AdministratorAccess':
                print(f"  WARNING: {user['UserName']} has AdministratorAccess via group '{group['GroupName']}'!")

print("\n" + "=" * 50)
print("Audit Complete")
print("=" * 50)