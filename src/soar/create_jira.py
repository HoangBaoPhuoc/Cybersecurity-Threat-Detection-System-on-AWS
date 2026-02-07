import os
import json
import logging
import base64
import urllib.request
import urllib.error

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment Variables
JIRA_URL = os.environ.get('JIRA_URL')
JIRA_USER = os.environ.get('JIRA_USER')
JIRA_API_TOKEN = os.environ.get('JIRA_API_TOKEN')
JIRA_PROJECT_KEY = os.environ.get('JIRA_PROJECT_KEY', 'SEC')
OPENSEARCH_ENDPOINT = os.environ.get('OPENSEARCH_ENDPOINT', 'localhost')

def lambda_handler(event, context):
    """
    Creates a Jira Issue for a security alert.
    Event payload: {"severity": "MEDIUM", "score": 0.45, "original_log": {...}, ...}
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    if not JIRA_URL or not JIRA_USER or not JIRA_API_TOKEN:
        logger.error("Missing Jira Configuration")
        return {"status": "SKIPPED", "reason": "Missing Jira Config"}

    try:
        # Construct Issue Payload
        log = event.get('original_log', {})
        
        # Dashboard Link
        dashboard_url = f"https://{OPENSEARCH_ENDPOINT}/_dashboards/app/discover"
        
        summary = f"[Security Alert] {event.get('severity', 'MEDIUM')} suspicious activity from {log.get('ip', 'Unknown IP')}"
        description = f"""
        *Security Incident Detected*
        
        *Severity:* {event.get('severity', 'MEDIUM')}
        *Risk Score:* {event.get('score', 0)}
        *User:* {log.get('user', 'Unknown')}
        *IP:* {log.get('ip', 'Unknown')}
        *Reasoning:* {event.get('reasoning', 'AI Anomaly Detection')}
        
        *Investigate in SIEM:* [{dashboard_url}|{dashboard_url}]
        
        *Raw Log:*
        {{code}}
        {json.dumps(log, indent=2)}
        {{code}}
        """

        issue_dict = {
            "fields": {
                "project": {"key": JIRA_PROJECT_KEY},
                "summary": summary,
                "description": description,
                "issuetype": {"name": "Task"},
                "priority": {"name": "High" if event.get('severity') in ['HIGH', 'CRITICAL'] else "Medium"}
            }
        }
        
        # Prepare Request
        url = f"{JIRA_URL}/rest/api/2/issue" # Use v2 for string description support
        data = json.dumps(issue_dict).encode('utf-8')
        
        # Auth Header
        auth_str = f"{JIRA_USER}:{JIRA_API_TOKEN}"
        b64_auth = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
        
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/json')
        req.add_header('Authorization', f"Basic {b64_auth}")
        
        # Execute Request
        with urllib.request.urlopen(req) as response:
            resp_body = response.read()
            logger.info("Jira Ticket Created Successfully")
            return json.loads(resp_body)
            
    except urllib.error.HTTPError as e:
        logger.error(f"Jira API Error: {e.code} - {e.read()}")
        return {"status": "FAILED", "reason": str(e)}
    except Exception as e:
        logger.error(f"Internal Error: {e}")
        return {"status": "ERROR", "reason": str(e)}
