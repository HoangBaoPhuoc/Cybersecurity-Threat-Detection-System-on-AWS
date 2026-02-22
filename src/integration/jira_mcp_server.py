import logging
import os

import requests
from flask import Flask, jsonify, request

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("JiraMCPServer")

app = Flask(__name__)

JIRA_URL = os.getenv("JIRA_URL", "")
JIRA_USER = os.getenv("JIRA_USER", "")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN", "")
JIRA_PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY", "SEC")


def _jira_request(payload):
    if not JIRA_URL or not JIRA_USER or not JIRA_API_TOKEN:
        return {"status": "ERROR", "reason": "Missing Jira configuration"}, 500

    auth = (JIRA_USER, JIRA_API_TOKEN)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    response = requests.post(
        f"{JIRA_URL}/rest/api/2/issue",
        headers=headers,
        auth=auth,
        json=payload,
        timeout=10
    )

    if response.status_code >= 400:
        return {"status": "ERROR", "reason": response.text}, response.status_code

    return response.json(), 200


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/tickets")
def create_ticket():
    body = request.get_json(silent=True) or {}
    summary = body.get("summary", "SOC Alert")
    description = body.get("description", "")
    priority = body.get("priority", "High")

    payload = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": summary,
            "description": description,
            "issuetype": {"name": "Incident"},
            "priority": {"name": priority}
        }
    }

    response, status_code = _jira_request(payload)
    return jsonify(response), status_code


if __name__ == "__main__":
    logger.info("Starting Jira MCP server on port 8080")
    app.run(host="0.0.0.0", port=8080)
