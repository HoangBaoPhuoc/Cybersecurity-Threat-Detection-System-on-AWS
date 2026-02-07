import boto3
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam = boto3.client('iam')

def lambda_handler(event, context):
    """
    AWS Lambda handler to disable an IAM User profile.
    Event payload: {"original_log": {"user": "admin", ...}, ...}
    """
    try:
        logger.info(f"Received event: {json.dumps(event)}")
        
        user = event.get('original_log', {}).get('user')
        
        if not user or user == 'unknown':
            logger.warning("No valid IAM username provided. Skipping disable action.")
            return {"status": "SKIPPED", "reason": "No valid user"}

        # Check if user exists (Mock check or real call)
        # In a real scenario, we might want to check if it's a critical system user first.
        
        logger.info(f"attempting to disable login profile for user: {user}")
        
        try:
            iam.delete_login_profile(UserName=user)
            logger.info(f"Successfully disabled login profile for user {user}")
            return {"status": "SUCCESS", "action": "DisableUser", "user": user}
            
        except iam.exceptions.NoSuchEntityException:
             logger.warning(f"User {user} or login profile does not exist.")
             return {"status": "SKIPPED", "reason": "User/Profile not found"}
             
    except Exception as e:
        logger.error(f"Error disabling user: {e}")
        return {"status": "ERROR", "reason": str(e)}
