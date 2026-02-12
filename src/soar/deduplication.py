import boto3
import os
import json
import logging
import time
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')
TABLE_NAME = os.environ.get('DYNAMODB_TABLE')
TTL_SECONDS = int(os.environ.get('DEDUP_TTL', 3600))  # Default 1 hour

def lambda_handler(event, context):
    """
    Checks if an alert for the same entity is already active.
    Event: {"original_log": {"ip": "1.2.3.4", ...}, "severity": "HIGH", ...}
    Returns: {"is_duplicate": bool, "dedup_id": str}
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    if not TABLE_NAME:
        logger.error("DYNAMODB_TABLE environment variable not set")
        return {"status": "ERROR", "reason": "Missing Config"}

    table = dynamodb.Table(TABLE_NAME)
    
    # Identify Entity (IP or User)
    log = event.get('original_log', {})
    entity_id = log.get('ip') or log.get('src_ip') or log.get('user') or 'unknown'
    rule_name = event.get('reasoning', 'GeneralAlert')
    
    dedup_key = f"{entity_id}::{rule_name}"
    
    try:
        # Check if item exists
        response = table.get_item(Key={'dedup_id': dedup_key})
        
        if 'Item' in response:
            # Alert exists
            item = response['Item']
            # Check if active (TTL check is handled by DynamoDB for deletion, but we check logically here if needed)
            # Actually, if it's there, it's a dupe.
            logger.info(f"Duplicate alert found for {dedup_key}")
            return {
                "is_duplicate": True, 
                "dedup_id": dedup_key,
                "ticket_id": item.get('ticket_id'),
                "original_event": event
            }
        else:
            # New Alert - We don't save it here yet? 
            # Strategy: Save it "Pending" or let the next step confirm ticket creation?
            # Better: This Step checks. If New, Step Function proceeds to Create Ticket, 
            # then updates this table with Ticket ID.
            # OR: We write it now with logic "If I say it's new, I reserve it".
            
            expiration = int(time.time()) + TTL_SECONDS
            table.put_item(
                Item={
                    'dedup_id': dedup_key,
                    'status': 'PENDING',
                    'created_at': int(time.time()),
                    'ttl': expiration
                }
            )
            logger.info(f"New alert registered for {dedup_key}")
            return {
                "is_duplicate": False, 
                "dedup_id": dedup_key,
                "original_event": event
            }

    except ClientError as e:
        logger.error(f"DynamoDB Error: {e}")
        return {"status": "ERROR", "reason": str(e)}
