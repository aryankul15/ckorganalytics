import boto3
import re
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

def assume_role(account_id, role_name):
    sts = boto3.client('sts')
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    try:
        creds = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="SupportCaseCheckSession"
        )['Credentials']
        return boto3.Session(
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken']
        )
    except ClientError as e:
        print(f"[{account_id}] Failed to assume role: {e}")
        return None

def get_support_plan(session):
    try:
        client = session.client('support', region_name='us-east-1')
        levels = client.describe_severity_levels()['severityLevels']
        codes = [lvl['code'] for lvl in levels]
        if 'critical' in codes:
            return 'Enterprise'
        elif 'urgent' in codes:
            return 'Business'
        elif set(codes) <= {'low', 'normal'}:
            return 'Developer'
        else:
            return 'Unknown'
    except ClientError as e:
        if e.response['Error']['Code'] == 'SubscriptionRequiredException':
            return 'Basic'
        print(f"Support plan check failed: {e}")
        return 'Error'

def get_quota_from_support_cases(session):
    try:
        client = session.client('support', region_name='us-east-1')
        six_months_ago = (datetime.utcnow() - timedelta(days=180)).isoformat()
        cases = client.describe_cases(
            includeResolvedCases=True,
            afterTime=six_months_ago,
            maxResults=100
        )['cases']

        max_found = None
        regex = re.compile(r'(?:increase|increased|set to|updated to|changed to)[^\d]{0,10}(\d{2,5})', re.IGNORECASE)

        for case in cases:
            if 'quota' in case['subject'].lower() or 'limit' in case['subject'].lower():
                comms = client.describe_communications(caseId=case['caseId'])
                for msg in comms.get('communications', []):
                    matches = regex.findall(msg.get('body', ''))
                    for m in matches:
                        val = int(m)
                        if val > 10:  # sanity check
                            max_found = max(max_found or 0, val)
        return max_found
    except ClientError as e:
        if e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print("No support access (Basic plan).")
            return None
        print(f"Error scanning support cases: {e}")
        return None

# ---------- MAIN EXECUTION FOR TESTING ----------
if __name__ == "__main__":
    account_id = "533116124383"     # Replace with your test account ID
    role_name = "Ergokrates-SSO-Role"  # Replace with role

    session = assume_role(account_id, role_name)
    if not session:
        exit(1)

    plan = get_support_plan(session)
    print(f"Support plan for {account_id}: {plan}")

    if plan in ['Business', 'Enterprise']:
        quota = get_quota_from_support_cases(session)
        if quota:
            print(f"Manual quota found via support case: {quota}")
        else:
            print("No relevant quota update found in support cases.")
    else:
        print("Support plan does not allow support case access.")
