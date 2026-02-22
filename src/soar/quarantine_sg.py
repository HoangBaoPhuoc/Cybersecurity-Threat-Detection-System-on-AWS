import json
import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client("ec2")
QUARANTINE_SG_ID = os.getenv("QUARANTINE_SG_ID", "")


def lambda_handler(event, context):
    logger.info(f"Received event: {json.dumps(event)}")

    instance_id = event.get("instance_id") or event.get("original_event", {}).get("instance_id")
    if not instance_id or not QUARANTINE_SG_ID:
        return {"status": "FAILED", "reason": "Missing instance_id or QUARANTINE_SG_ID"}

    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[QUARANTINE_SG_ID]
    )

    return {"status": "SUCCESS", "instance_id": instance_id, "sg": QUARANTINE_SG_ID}
