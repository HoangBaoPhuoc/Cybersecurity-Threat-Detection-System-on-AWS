import boto3
import os
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam = boto3.client('iam')
DENY_POLICY_ARN = os.environ.get('DENY_POLICY_ARN')

def lambda_handler(event, context):
    """
    Attaches a DenyAll policy to the user.
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    user = event.get('original_event', {}).get('original_log', {}).get('user')
    
    if not user or not DENY_POLICY_ARN:
        return {"status": "FAILED", "reason": "Missing User or Policy ARN"}

    # --- GUARDRAIL CHECK ---
    try:
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table('entity-risk-state')
        entity_id = f"user:{user}"
        response = table.get_item(Key={'entity_id': entity_id})
        
        allowed = False
        if 'Item' in response:
            score = float(response['Item'].get('cumulative_risk_score', 0))
            # Higher threshold for complete account restriction? Let's stick to 70 as requested.
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

    try:
        iam.attach_user_policy(
            UserName=user,
            PolicyArn=DENY_POLICY_ARN
        )
        return {"status": "SUCCESS", "action": "Msg User Restricted", "user": user}

    except Exception as e:
        logger.error(f"IAM Restrict Error: {e}")
        return {"status": "ERROR", "reason": str(e)}
