import os
import json
import boto3
import requests
from requests.auth import HTTPBasicAuth
from datetime import datetime

# Configuration
OPENSEARCH_HOST = os.environ['OPENSEARCH_HOST']
OPENSEARCH_INDEX = "aws-config-findings"
OPENSEARCH_USER = "admin" 
OPENSEARCH_PASS = "Admin123!" 

def lambda_handler(event, context):
    """
    Transforms AWS Config Compliance Change Events and sends to OpenSearch.
    """
    print(f"Received Event: {json.dumps(event)}")
    
    try:
        detail = event.get('detail', {})
        resource_id = detail.get('resourceId')
        resource_type = detail.get('resourceType')
        config_rule_name = detail.get('configRuleName')
        new_evaluation_result = detail.get('newEvaluationResult', {})
        compliance_type = new_evaluation_result.get('complianceType')
        annotation = new_evaluation_result.get('annotation') or "No annotation"
        
        if compliance_type != "NON_COMPLIANT":
            print(f"Resource {resource_id} is {compliance_type}. Skipping index.")
            return

        # Unique ID for the finding
        finding_id = f"{config_rule_name}-{resource_id}-{datetime.utcnow().timestamp()}"

        # Construct Document
        document = {
            "finding_id": finding_id,
            "timestamp": detail.get('recordVersion') or datetime.utcnow().isoformat(),
            "type": "ComplianceViolation",
            "severity": "MEDIUM", # Default severity for Config violations
            "title": f"Non-Compliant: {config_rule_name}",
            "description": f"Resource {resource_id} ({resource_type}) is NON_COMPLIANT. Annotation: {annotation}",
            "resource_id": resource_id,
            "resource_type": resource_type,
            "rule_name": config_rule_name,
            "service": "aws-config",
            "account_id": event.get('account'),
            "region": event.get('region'),
            "raw_event": detail
        }
        
        # Send to OpenSearch
        url = f"https://{OPENSEARCH_HOST}/{OPENSEARCH_INDEX}/_doc/{finding_id}"
        headers = {"Content-Type": "application/json"}
        
        response = requests.post(
            url, 
            auth=HTTPBasicAuth(OPENSEARCH_USER, OPENSEARCH_PASS),
            json=document,
            timeout=5,
            verify=False 
        )
        
        if response.status_code in [200, 201]:
            print(f"Successfully indexed violation {finding_id}")
        else:
            print(f"Failed to index violation. Status: {response.status_code}, Error: {response.text}")
            raise Exception(f"OpenSearch indexing failed: {response.text}")

    except Exception as e:
        print(f"Error processing Config event: {str(e)}")
        raise e
