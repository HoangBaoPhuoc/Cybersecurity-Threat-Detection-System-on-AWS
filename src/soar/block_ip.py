import boto3
import os
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client('ec2')

# Environment variable for the VPC ID or Subnet ID to find the correct NACL
VPC_ID = os.environ.get('VPC_ID') 

def lambda_handler(event, context):
    """
    AWS Lambda handler to block an IP address using Network ACLs.
    Event payload: {"ip": "1.2.3.4", "severity": "HIGH", ...}
    """
    try:
        logger.info(f"Received event: {json.dumps(event)}")
        
        ip_to_block = event.get('original_log', {}).get('ip') or event.get('original_log', {}).get('src_ip') or event.get('ip')
        
        if not ip_to_block:
            logger.error("No IP address found in event payload.")
            return {"status": "FAILED", "reason": "No IP address provided"}

        # --- GUARDRAIL CHECK ---
        try:
            dynamodb = boto3.resource('dynamodb')
            table = dynamodb.Table('entity-risk-state')
            entity_id = f"ip:{ip_to_block}"
            response = table.get_item(Key={'entity_id': entity_id})
            
            allowed = False
            if 'Item' in response:
                score = float(response['Item'].get('cumulative_risk_score', 0))
                if score >= 70:
                    allowed = True
                else:
                    logger.warning(f"Guardrail Blocked: Risk Score {score} < 70 for {entity_id}")
            else:
                logger.warning(f"Guardrail Blocked: No risk state found for {entity_id}")

            if not allowed:
                return {"status": "SKIPPED", "reason": "Risk Score below threshold", "action": "None"}

        except Exception as e:
            logger.error(f"Guardrail Check Failed: {e}")
            return {"status": "ERROR", "reason": "Guardrail Check Failed"}
        # -----------------------

        # 1. Find the Network ACL associated with the public subnets (or specific subnets)
        # For simplicity, we look for NACLs in the VPC. In a real scenario, filter by Subnet ID.
        response = ec2.describe_network_acls(
            Filters=[{'Name': 'vpc-id', 'Values': [VPC_ID]}]
        )
        
        # Assume the first NACL is the one we want to update (or filter by tag)
        if not response['NetworkAcls']:
            logger.error(f"No Network ACL found for VPC {VPC_ID}")
            return {"status": "FAILED", "reason": "NACL not found"}
            
        nacl_id = response['NetworkAcls'][0]['NetworkAclId']
        existing_entries = response['NetworkAcls'][0]['Entries']
        
        # 2. Determine next Rule Number (Start from 50, go down or up. AWS limits 20 rules usually? No, much higher)
        # We will use entries 50-99 for blocking.
        used_rules = [e['RuleNumber'] for e in existing_entries if 50 <= e['RuleNumber'] < 100]
        new_rule_number = 50
        while new_rule_number in used_rules:
            new_rule_number += 1
            
        if new_rule_number >= 100:
             logger.error("NACL Rule limit reached for blocking range (50-99).")
             return {"status": "FAILED", "reason": "NACL Rule limit reached"}

        # 3. Create Network ACL Entry (DENY)
        logger.info(f"Blocking IP {ip_to_block} on NACL {nacl_id} with Rule {new_rule_number}")
        
        ec2.create_network_acl_entry(
            NetworkAclId=nacl_id,
            RuleNumber=new_rule_number,
            Protocol='-1', # All protocols
            RuleAction='deny',
            Egress=False, # Inbound
            CidrBlock=f"{ip_to_block}/32",
            PortRange={'From': 0, 'To': 65535}
        )
        
        return {
            "status": "SUCCESS", 
            "action": "BlockIP", 
            "ip": ip_to_block, 
            "nacl_id": nacl_id, 
            "rule_number": new_rule_number
        }

    except Exception as e:
        logger.error(f"Error blocking IP: {e}")
        return {"status": "ERROR", "reason": str(e)}
