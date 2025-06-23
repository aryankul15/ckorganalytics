import boto3
import json
import re
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

def load_accounts_from_json(file_path):
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading JSON: {e}")
        return []

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
        two_years_ago = (datetime.utcnow() - timedelta(days=730)).isoformat()
        
        cases = []
        next_token = None
        while True:
            params = {
                'includeResolvedCases': True,
                'afterTime': two_years_ago,
                'maxResults': 100
            }
            if next_token:
                params['nextToken'] = next_token

            resp = client.describe_cases(**params)
            cases.extend(resp.get('cases', []))
            next_token = resp.get('nextToken')
            if not next_token:
                break

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
            print("  No support access (Basic plan).")
            return None
        print(f"  Error scanning support cases: {e}")
        return None

def main():
    json_path = "accounts.json"  # Update if named differently
    accounts = load_accounts_from_json(json_path)
    if not accounts:
        print("No valid accounts found.")
        return

    for acct in accounts:
        account_id = acct['account_id']
        role_name = acct['role_name']
        print(f"\n🔍 Processing account: {account_id}")

        session = assume_role(account_id, role_name)
        if not session:
            continue

        plan = get_support_plan(session)
        print(f"  📦 Support plan: {plan}")

        if plan in ['Business', 'Enterprise']:
            quota = get_quota_from_support_cases(session)
            if quota:
                print(f"  ✅ Quota found via support case: {quota}")
            else:
                print("  ❌ No relevant quota update found in support cases.")
        else:
            print("  ⚠️  Skipping support case scan (insufficient support plan)")

if __name__ == "__main__":
    main()
