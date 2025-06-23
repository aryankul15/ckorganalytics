import boto3
import json
import csv
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError, NoCredentialsError
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def load_accounts_from_json(file_path):
    """Load account IDs and role names from JSON file"""
    try:
        with open(file_path, 'r') as f:
            accounts = json.load(f)
        logger.info(f"Loaded {len(accounts)} accounts from {file_path}")
        return accounts
    except FileNotFoundError:
        logger.error(f"File {file_path} not found")
        return []
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON in {file_path}")
        return []

def assume_role(account_id, role_name):
    """Assume role in target account and return session"""
    try:
        sts_client = boto3.client('sts')
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f'quota-checker-{account_id}'
        )
        
        credentials = response['Credentials']
        session = boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        
        logger.info(f"Successfully assumed role in account {account_id}")
        return session
    
    except ClientError as e:
        logger.error(f"Failed to assume role in account {account_id}: {e}")
        return None

def get_account_aliases(session):
    """Get account aliases using IAM client"""
    try:
        iam_client = session.client('iam')
        response = iam_client.list_account_aliases()
        aliases = response.get('AccountAliases', [])
        return ', '.join(aliases) if aliases else 'No aliases'
    
    except ClientError as e:
        logger.error(f"Failed to get account aliases: {e}")
        return 'Error getting aliases'

def get_organization_accounts(session):
    """Get all accounts in the organization with pagination"""
    try:
        org_client = session.client('organizations')
        accounts = []
        
        paginator = org_client.get_paginator('list_accounts')
        for page in paginator.paginate():
            accounts.extend(page['Accounts'])
        
        logger.info(f"Found {len(accounts)} accounts in organization")
        return accounts
    
    except ClientError as e:
        logger.error(f"Failed to get organization accounts: {e}")
        return []

def get_service_quota_history(session, quota_code='L-E619E033'):
    """Get service quota request history for organization accounts quota"""
    try:
        quota_client = session.client('service-quotas')
        
        # Get quota request history
        paginator = quota_client.get_paginator('list_requested_service_quota_change_history_by_quota')
        requests = []
        
        for page in paginator.paginate(ServiceCode='organizations', QuotaCode=quota_code, Status='CASE_CLOSED'):
            requests.extend(page['RequestedQuotas'])
        
        # Filter approved requests and get the latest one
        approved_requests = [req for req in requests if req['Status'] == 'CASE_CLOSED']
        
        if approved_requests:
            # Sort by creation time and get the latest
            latest_request = max(approved_requests, key=lambda x: x['Created'])
            return int(latest_request['DesiredValue'])
        
        return None
    
    except ClientError as e:
        logger.error(f"Failed to get quota history: {e}")
        return None

def get_default_quota(session, quota_code='L-E619E033'):
    """Get default service quota for organization accounts"""
    try:
        quota_client = session.client('service-quotas')
        
        response = quota_client.get_service_quota(
            ServiceCode='organizations',
            QuotaCode=quota_code
        )
        
        return int(response['Quota']['Value'])
    
    except ClientError as e:
        # If no custom quota exists, get the default
        try:
            response = quota_client.get_aws_default_service_quota(
                ServiceCode='organizations',
                QuotaCode=quota_code
            )
            return int(response['Quota']['Value'])
        except ClientError as e2:
            logger.error(f"Failed to get default quota: {e2}")
            return 0

def get_support_plan(session):
    """
    Determine the AWS Support plan by calling describe_severity_levels.
    Basic plan -> SubscriptionRequiredException
    Developer -> only low & normal
    Business  -> includes 'urgent'
    Enterprise-> includes 'critical'
    """
    try:
        support_client = session.client('support', region_name='us-east-1')
        response = support_client.describe_severity_levels(language='en')
        codes = [sev['code'] for sev in response['severityLevels']]
        
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
        logger.error(f"Failed to get support plan: {e}")
        return 'Error'

def calculate_buffer(max_accounts, current_accounts):
    """Calculate buffer for account creation"""
    return max_accounts - current_accounts

def process_account(account_data):
    """Process a single account - main worker function"""
    account_id = account_data['account_id']
    role_name = account_data['role_name']
    
    logger.info(f"Processing account {account_id}")
    
    # Initialize result with account ID
    result = {
        'Account_Id': account_id,
        'Account_Aliases': 'Error',
        'No_of_Accounts_in_Org': 0,
        'Current_Maximum_Quota': 0,
        'Buffer': 0,
        'Support_Plan': 'Error'
    }
    
    try:
        # Assume role
        session = assume_role(account_id, role_name)
        if not session:
            return result
        
        # Get account aliases
        result['Account_Aliases'] = get_account_aliases(session)
        
        # Get organization accounts
        org_accounts = get_organization_accounts(session)
        result['No_of_Accounts_in_Org'] = len(org_accounts)
        
        # Get service quota (check history first, then default)
        quota_code = 'L-E619E033'  # Organizations account quota code
        max_quota = get_service_quota_history(session, quota_code)
        
        if max_quota is None:
            max_quota = get_default_quota(session, quota_code)
        
        result['Current_Maximum_Quota'] = max_quota
        
        # Calculate buffer
        result['Buffer'] = calculate_buffer(max_quota, len(org_accounts))
        
        # Get support plan
        result['Support_Plan'] = get_support_plan(session)
        
        logger.info(f"Successfully processed account {account_id}")
        
    except Exception as e:
        logger.error(f"Error processing account {account_id}: {e}")
    
    return result

def export_to_csv(results, filename='organization_quota_report.csv'):
    """Export results to CSV file"""
    try:
        fieldnames = ['Account_Id', 'Account_Aliases', 'No_of_Accounts_in_Org', 
                     'Current_Maximum_Quota', 'Buffer', 'Support_Plan']
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)
        
        logger.info(f"Results exported to {filename}")
        
    except Exception as e:
        logger.error(f"Failed to export to CSV: {e}")

def main():
    """Main function to orchestrate the process"""
    
    # Configuration
    json_file_path = 'accounts.json'  # Path to your JSON file
    output_csv = 'organization_quota_report.csv'
    max_workers = 5  # Adjust based on your needs and AWS limits
    
    logger.info("Starting AWS Organization Quota Checker")
    
    # Load accounts from JSON
    accounts = load_accounts_from_json(json_file_path)
    if not accounts:
        logger.error("No accounts loaded. Exiting.")
        return
    
    # Process accounts using ThreadPoolExecutor
    results = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_account = {
            executor.submit(process_account, account): account 
            for account in accounts
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_account):
            account = future_to_account[future]
            try:
                result = future.result()
                results.append(result)
                logger.info(f"Completed processing account {account['account_id']}")
            except Exception as e:
                logger.error(f"Account {account['account_id']} generated exception: {e}")
    
    # Export results to CSV
    if results:
        export_to_csv(results, output_csv)
        logger.info(f"Processing complete. {len(results)} accounts processed.")
    else:
        logger.warning("No results to export")


if __name__ == "__main__":
    main()