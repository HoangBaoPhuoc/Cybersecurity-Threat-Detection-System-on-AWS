import requests
import json
import os

class JiraClient:
    def __init__(self, domain, email, api_token):
        self.base_url = f"https://{domain}.atlassian.net/rest/api/3"
        self.auth = (email, api_token)
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

    def create_incident(self, project_key, summary, description, priority="High"):
        url = f"{self.base_url}/issue"
        
        payload = {
            "fields": {
                "project": {
                    "key": project_key
                },
                "summary": summary,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "type": "text",
                                    "text": description
                                }
                            ]
                        }
                    ]
                },
                "issuetype": {
                    "name": "Incident" # Ensure this issue type exists in your Jira project
                },
                "priority": {
                    "name": priority
                }
            }
        }

        try:
            response = requests.post(url, headers=self.headers, auth=self.auth, data=json.dumps(payload))
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            print(f"Error creating Jira ticket: {e.response.text}")
            return None

# Usage Example
if __name__ == "__main__":
    # Ensure env vars are set or replace with mock data for testing
    domain = os.getenv("JIRA_DOMAIN", "your-domain")
    email = os.getenv("JIRA_EMAIL", "user@example.com")
    token = os.getenv("JIRA_TOKEN", "your-api-token")
    
    if "your-" not in domain:
        client = JiraClient(domain, email, token)
        result = client.create_incident("SEC", "Test Security Incident", "This is a test incident created by the Threat Detection System.")
        print(result)
    else:
        print("Skipping execution: Jira credentials not set.")
