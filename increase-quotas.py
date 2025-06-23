# import boto3
# client = boto3.client('service-quotas')

# # response = client.get_service_quota(
# #     ServiceCode='organizations',
# #     QuotaCode='L-E619E033'
# response = client.get_requested_service_quota_change(
#     RequestId='5ea1514c03eb4f2d97641d7750d18c6d79DwCAWF'
# )
# # )
# print(response)

import boto3
import json

client = boto3.client('service-quotas')

try:
    # List all quota change requests for organizations service
    response = client.list_requested_service_quota_change_history_by_quota(
        ServiceCode='organizations',
        QuotaCode='L-E619E033',
        Status='CASE_CLOSED'
    )
    
    # Print each request details
    for request in response['RequestedQuotas']:
        print("\nQuota Change Request Details:")
        print(f"Request ID: {request['Id']}")
        print(f"Service Code: {request['ServiceCode']}")
        print(f"Service Name: {request['ServiceName']}")
        print(f"Quota Code: {request['QuotaCode']}")
        print(f"Quota Name: {request['QuotaName']}")
        print(f"Desired Value: {request['DesiredValue']}")
        print(f"Status: {request['Status']}")
        print(f"Created: {request['Created']}")
        if 'Case' in request:
            print(f"Case ID: {request['Case']}")

except Exception as e:
    print(f"Error: {str(e)}")