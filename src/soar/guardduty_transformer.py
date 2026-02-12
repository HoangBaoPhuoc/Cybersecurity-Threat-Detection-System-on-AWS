import os
import json
import boto3
import requests
from requests.auth import HTTPBasicAuth
from datetime import datetime

# Configuration
OPENSEARCH_HOST = os.environ['OPENSEARCH_HOST'] # format: domain.region.es.amazonaws.com
OPENSEARCH_INDEX = "guardduty-findings"
# For demo, using admin/password. In prod, use SigV4 or IAM
OPENSEARCH_USER = "admin" 
OPENSEARCH_PASS = "Admin123!" 

def lambda_handler(event, context):
    """
    Transforms GuardDuty Findings from EventBridge and sends to OpenSearch.
    """
    print(f"Received Event: {json.dumps(event)}")
    
    try:
        # Extract Finding Details
        detail = event.get('detail', {})
        finding_id = detail.get('id')
        finding_type = detail.get('type')
        severity = detail.get('severity')
        region = event.get('region')
        account = event.get('account')
        
        if not finding_id:
            print("No finding ID found. Skipping.")
            return
            
        # Construct Document for SIEM
        document = {
            "finding_id": finding_id,
            "timestamp": detail.get('updatedAt') or datetime.utcnow().isoformat(),
            "type": finding_type,
            "severity": severity,
            "account_id": account,
            "region": region,
            "title": detail.get('title'),
            "description": detail.get('description'),
            "resource_id": detail.get('resource', {}).get('instanceDetails', {}).get('instanceId') or "unknown",
            "service": "guardduty",
            "raw_finding": detail
        }
        
        # Send to OpenSearch
        url = f"https://{OPENSEARCH_HOST}/{OPENSEARCH_INDEX}/_doc/{finding_id}"
        headers = {"Content-Type": "application/json"}
        
        response = requests.post(
            url, 
            auth=HTTPBasicAuth(OPENSEARCH_USER, OPENSEARCH_PASS),
            json=document,
            timeout=5,
            verify=False # AWS Internal/Self-Signed, skipping verify for demo
        )
        
        if response.status_code in [200, 201]:
            print(f"Successfully indexed finding {finding_id}")
        else:
            print(f"Failed to index finding. Status: {response.status_code}, Error: {response.text}")
            raise Exception(f"OpenSearch indexing failed: {response.text}")

    except Exception as e:
        print(f"Error processing finding: {str(e)}")
        raise e
