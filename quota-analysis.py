import boto3
import json
import csv
from botocore.exceptions import ClientError, NoCredentialsError
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def read_accounts_from_json(file_path):
    """Read account information from JSON file"""
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        logger.info(f"Successfully loaded {len(data)} accounts from {file_path}")
        return data
    except FileNotFoundError:
        logger.error(f"File {file_path} not found")
        return []
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON in file {file_path}")
        return []

def assume_role(account_id, role_name):
    """Assume role in the specified account"""
    try:
        sts_client = boto3.client('sts')
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"OrgAnalysis-{account_id}"
        )
        
        credentials = response['Credentials']
        return {
            'aws_access_key_id': credentials['AccessKeyId'],
            'aws_secret_access_key': credentials['SecretAccessKey'],
            'aws_session_token': credentials['SessionToken']
        }
    except ClientError as e:
        logger.error(f"Failed to assume role in account {account_id}: {e}")
        return None

def get_account_aliases(session_credentials):
    """Get account aliases for the current account"""
    try:
        iam_client = boto3.client('iam', **session_credentials)
        response = iam_client.list_account_aliases()
        aliases = response.get('AccountAliases', [])
        return ', '.join(aliases) if aliases else 'No aliases'
    except ClientError as e:
        logger.error(f"Failed to get account aliases: {e}")
        return 'Error retrieving aliases'

def get_organization_accounts(session_credentials):
    """Get all accounts in the organization with proper pagination"""
    try:
        org_client = boto3.client('organizations', **session_credentials)
        accounts = []
        
        # Use paginator for proper pagination handling
        paginator = org_client.get_paginator('list_accounts')
        page_iterator = paginator.paginate()
        
        for page in page_iterator:
            accounts.extend(page.get('Accounts', []))
        
        logger.info(f"Found {len(accounts)} accounts in organization")
        return len(accounts)
    except ClientError as e:
        logger.error(f"Failed to get organization accounts: {e}")
        return 'Error retrieving account count'
    
def list_service_quotas_for_accounts(session_credentials):
    """Get service quota for maximum accounts in organization"""
    try:
        quota_client = boto3.client('service-quotas', **session_credentials)
        
        # Service quota code for maximum accounts in organization
        response = quota_client.list_service_quotas(
            ServiceCode='organizations',
            QuotaCode='L-E619E033'  # Maximum accounts quota code
        )
        # print(data1['Quotas']['Value'])
        return int(response['Quotas'][0]['Value'])
    except ClientError as e:
        logger.error(f"Failed to get service quota: {e}")
        return 'Error retrieving quota'

def calculate_buffer(max_quota, current_accounts):
    """Calculate buffer for account creation"""
    try:
        if isinstance(max_quota, str) or isinstance(current_accounts, str):
            return 'Cannot calculate'
        return max_quota - current_accounts
    except:
        return 'Cannot calculate'

def process_accounts(accounts_data):
    """Process each account and gather required information"""
    results = []
    
    for account_info in accounts_data:
        account_id = account_info.get('account_id')
        role_name = account_info.get('role_name')
        
        if not account_id or not role_name:
            logger.warning(f"Missing account_id or role_name in: {account_info}")
            continue
        
        logger.info(f"Processing account: {account_id}")
        
        # Assume role
        session_credentials = assume_role(account_id, role_name)
        if not session_credentials:
            results.append({
                'Account_Id': account_id,
                'Account_Aliases': 'Role assumption failed',
                'No_of_Accounts_in_Org': 'N/A',
                'Current_Maximum_Quota': 'N/A',
                'Buffer_for_Account_Creation': 'N/A'
            })
            continue
        
        # Get account aliases
        account_aliases = get_account_aliases(session_credentials)
        
        # Get organization accounts count
        org_accounts_count = get_organization_accounts(session_credentials)
        
        # Get service quota
        max_quota = list_service_quotas_for_accounts(session_credentials)
        
        # Calculate buffer
        buffer = calculate_buffer(max_quota, org_accounts_count)
        
        results.append({
            'Account_Id': account_id,
            'Account_Aliases': account_aliases,
            'No_of_Accounts_in_Org': org_accounts_count,
            'Current_Maximum_Quota': max_quota,
            'Buffer_for_Account_Creation': buffer
        })
        
        logger.info(f"Completed processing account: {account_id}")
    
    return results

def export_to_csv(data, output_file):
    """Export data to CSV file"""
    try:
        headers = [
            'Account_Id',
            'Account_Aliases', 
            'No_of_Accounts_in_Org',
            'Current_Maximum_Quota',
            'Buffer_for_Account_Creation'
        ]
        
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()
            writer.writerows(data)
        
        logger.info(f"Data exported successfully to {output_file}")
    except Exception as e:
        logger.error(f"Failed to export data to CSV: {e}")

def main():
    """Main function to orchestrate the process"""
    # Configuration
    json_file_path = 'accounts.json'  # Update this path as needed
    output_csv_file = 'organization_analysis.csv'
    
    logger.info("Starting AWS Organization Analysis")
    
    # Read accounts from JSON
    accounts_data = read_accounts_from_json(json_file_path)
    if not accounts_data:
        logger.error("No accounts data found. Exiting.")
        return
    
    # Process accounts
    results = process_accounts(accounts_data)
    
    # Export to CSV
    export_to_csv(results, output_csv_file)
    
    logger.info("AWS Organization Analysis completed")
    
    # Print summary
    print(f"\nProcessed {len(results)} accounts")
    print(f"Results exported to: {output_csv_file}")

if __name__ == "__main__":
    main()