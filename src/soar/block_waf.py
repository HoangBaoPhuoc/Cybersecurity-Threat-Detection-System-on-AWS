import boto3
import os
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

wafv2 = boto3.client('wafv2')
IP_SET_ARN = os.environ.get('WAF_IP_SET_ARN')
IP_SET_NAME = os.environ.get('WAF_IP_SET_NAME')
IP_SET_ID = os.environ.get('WAF_IP_SET_ID')
SCOPE = os.environ.get('WAF_SCOPE', 'REGIONAL') # or CLOUDFRONT

def lambda_handler(event, context):
    """
    Blocks an IP by adding it to a WAF IP Set.
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    ip = event.get('original_event', {}).get('original_log', {}).get('ip')
    
    if not ip or not IP_SET_ARN:
        return {"status": "FAILED", "reason": "Missing IP or Config"}

    try:
        # 1. Get current LockToken
        response = wafv2.get_ip_set(
            Name=IP_SET_NAME,
            Scope=SCOPE,
            Id=IP_SET_ID
        )
        
        lock_token = response['LockToken']
        addresses = response['IPSet']['Addresses']
        
        cidr = f"{ip}/32"
        if cidr in addresses:
            return {"status": "SKIPPED", "reason": "IP already blocked"}
            
        addresses.append(cidr)
        
        # 2. Update IP Set
        wafv2.update_ip_set(
            Name=IP_SET_NAME,
            Scope=SCOPE,
            Id=IP_SET_ID,
            Addresses=addresses,
            LockToken=lock_token
        )
        
        return {"status": "SUCCESS", "action": "BlockWAF", "ip": ip}

    except Exception as e:
        logger.error(f"WAF Block Error: {e}")
        return {"status": "ERROR", "reason": str(e)}
