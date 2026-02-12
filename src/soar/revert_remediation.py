import boto3
import os
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

wafv2 = boto3.client('wafv2')
iam = boto3.client('iam')

# WAF Config
IP_SET_NAME = os.environ.get('WAF_IP_SET_NAME')
IP_SET_ID = os.environ.get('WAF_IP_SET_ID')
SCOPE = os.environ.get('WAF_SCOPE', 'REGIONAL')

# IAM Config
DENY_POLICY_ARN = os.environ.get('DENY_POLICY_ARN')

def lambda_handler(event, context):
    """
    Reverts remediation actions (Unblock WAF, Detach IAM Policy).
    Event: includes "ip" and "user" from previous steps.
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    results = {}
    
    # 1. Revert WAF
    ip = event.get('original_event', {}).get('original_log', {}).get('ip')
    if ip and IP_SET_ID:
        try:
            resp = wafv2.get_ip_set(Name=IP_SET_NAME, Scope=SCOPE, Id=IP_SET_ID)
            lock_token = resp['LockToken']
            addresses = resp['IPSet']['Addresses']
            cidr = f"{ip}/32"
            
            if cidr in addresses:
                addresses.remove(cidr)
                wafv2.update_ip_set(
                    Name=IP_SET_NAME, Scope=SCOPE, Id=IP_SET_ID,
                    Addresses=addresses, LockToken=lock_token
                )
                results['waf'] = "Unblocked"
        except Exception as e:
            results['waf_error'] = str(e)

    # 2. Revert IAM
    user = event.get('original_event', {}).get('original_log', {}).get('user')
    if user and DENY_POLICY_ARN:
        try:
            iam.detach_user_policy(UserName=user, PolicyArn=DENY_POLICY_ARN)
            results['iam'] = "Unrestricted"
        except Exception as e:
            results['iam_error'] = str(e)
            
    return {"status": "SUCCESS", "results": results}
