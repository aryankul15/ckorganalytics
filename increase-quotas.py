import boto3
import json
client = boto3.client('service-quotas')

response = client.list_service_quotas(
    ServiceCode='organizations',
    QuotaCode='L-E619E033'
)
data =response["Quotas"][0]
print(data["Value"])