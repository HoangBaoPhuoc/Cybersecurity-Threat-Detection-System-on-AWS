import json
import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ssm = boto3.client("ssm")
RUNBOOK_NAME = os.getenv("SSM_RUNBOOK_NAME", "")


def lambda_handler(event, context):
    logger.info(f"Received event: {json.dumps(event)}")

    if not RUNBOOK_NAME:
        return {"status": "FAILED", "reason": "Missing SSM_RUNBOOK_NAME"}

    parameters = event.get("parameters", {})

    response = ssm.start_automation_execution(
        DocumentName=RUNBOOK_NAME,
        Parameters=parameters
    )

    return {
        "status": "SUCCESS",
        "automation_execution_id": response.get("AutomationExecutionId")
    }
