import os
import json
import logging
import base64
import urllib.request
import urllib.error

logger = logging.getLogger()
logger.setLevel(logging.INFO)

JIRA_URL = os.environ.get('JIRA_URL')
JIRA_USER = os.environ.get('JIRA_USER')
JIRA_API_TOKEN = os.environ.get('JIRA_API_TOKEN')

def lambda_handler(event, context):
    """
    Updates a Jira Issue (Add Comment or Transition).
    Event: {
        "ticket_id": "SEC-123", 
        "action": "ADD_COMMENT" | "TRANSITION", 
        "comment": "...", 
        "transition_id": "..."
    }
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    ticket_id = event.get('ticket_id')
    if not ticket_id:
        return {"status": "SKIPPED", "reason": "No Ticket ID"}

    try:
        # Auth
        auth_str = f"{JIRA_USER}:{JIRA_API_TOKEN}"
        b64_auth = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f"Basic {b64_auth}"
        }

        # Action: Add Comment
        if event.get('action') == 'ADD_COMMENT':
            url = f"{JIRA_URL}/rest/api/2/issue/{ticket_id}/comment"
            comment_body = event.get('comment', 'System Update')
            payload = {"body": comment_body}
            
            data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(url, data=data, headers=headers, method='POST')
            urllib.request.urlopen(req)
            return {"status": "SUCCESS", "action": "Comment Added"}

        # Action: Transition (e.g., to In Progress or Done)
        # Note: Need Transition IDs specific to Jira Workflow.
        elif event.get('action') == 'TRANSITION':
            # Not fully implemented without ID discovery, skipping for safe boilerplate
            pass

        return {"status": "SUCCESS", "message": "No action taken"}

    except Exception as e:
        logger.error(f"Jira Update Error: {e}")
        return {"status": "ERROR", "reason": str(e)}
