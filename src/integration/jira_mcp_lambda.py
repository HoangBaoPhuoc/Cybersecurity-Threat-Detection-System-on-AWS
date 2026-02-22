import json
import logging
import os

import urllib.request
import base64

logger = logging.getLogger("JiraMCPLambda")
logger.setLevel(logging.INFO)

JIRA_URL = os.getenv("JIRA_URL", "")
JIRA_USER = os.getenv("JIRA_USER", "")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN", "")
JIRA_PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY", "SEC")


def _create_issue(summary, description, priority):
    if not JIRA_URL or not JIRA_USER or not JIRA_API_TOKEN:
        return {"status": "ERROR", "reason": "Missing Jira configuration"}

    issue = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": summary,
            "description": description,
            "issuetype": {"name": "Incident"},
            "priority": {"name": priority}
        }
    }

    url = f"{JIRA_URL}/rest/api/2/issue"
    data = json.dumps(issue).encode("utf-8")

    auth_str = f"{JIRA_USER}:{JIRA_API_TOKEN}"
    b64_auth = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")

    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Basic {b64_auth}")

    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read())


def lambda_handler(event, context):
    method = event.get("requestContext", {}).get("http", {}).get("method", "POST")
    path = event.get("requestContext", {}).get("http", {}).get("path", "/")

    if method == "GET" and path.endswith("/health"):
        return {"statusCode": 200, "body": json.dumps({"status": "ok"})}

    body = event.get("body")
    if isinstance(body, str):
        payload = json.loads(body) if body else {}
    else:
        payload = body or {}

    summary = payload.get("summary", "SOC Alert")
    description = payload.get("description", "")
    priority = payload.get("priority", "High")

    try:
        result = _create_issue(summary, description, priority)
        return {"statusCode": 200, "body": json.dumps(result)}
    except Exception as exc:
        logger.error(f"Jira MCP error: {exc}")
        return {"statusCode": 500, "body": json.dumps({"status": "ERROR", "reason": str(exc)})}
