import os
import time
import json
import requests
from requests.auth import HTTPBasicAuth
import logging

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# Configuration
OPENSEARCH_HOST = os.environ.get('OPENSEARCH_HOST', 'localhost')
OPENSEARCH_PORT = os.environ.get('OPENSEARCH_PORT', '443') 
OPENSEARCH_USER = "admin"
OPENSEARCH_PASS = "Admin123!"
BASE_URL = f"https://{OPENSEARCH_HOST}:{OPENSEARCH_PORT}"
AUTH = HTTPBasicAuth(OPENSEARCH_USER, OPENSEARCH_PASS)
HEADERS = {"Content-Type": "application/json", "kbn-xsrf": "true"}

def wait_for_opensearch():
    logger.info(f"Waiting for OpenSearch at {BASE_URL}...")
    while True:
        try:
            resp = requests.get(BASE_URL, auth=AUTH, verify=False, timeout=5)
            if resp.status_code == 200:
                logger.info("OpenSearch is up and running!")
                break
        except Exception as e:
            logger.warning(f"Connection failed: {e}. Retrying in 10s...")
        time.sleep(10)

def create_index_pattern(pattern_name, time_field="@timestamp"):
    # Change specific time fields depending on index if needed, otherwise default
    url = f"{BASE_URL}/_dashboards/api/saved_objects/index-pattern/{pattern_name}"
    payload = {
        "attributes": {
            "title": pattern_name,
            "timeFieldName": time_field
        }
    }
    try:
        resp = requests.post(url, auth=AUTH, headers=HEADERS, json=payload, verify=False)
        if resp.status_code in [200, 201]:
            logger.info(f"Index pattern {pattern_name} created.")
        elif resp.status_code == 409:
            logger.info(f"Index pattern {pattern_name} already exists.")
        else:
            logger.error(f"Failed to create index pattern {pattern_name}: {resp.text}")
    except Exception as e:
        logger.error(f"Error creating index pattern {pattern_name}: {e}")

def create_monitor(name, indices, query_dsl, severity="1"):
    url = f"{BASE_URL}/_plugins/_alerting/monitors"
    
    # Check if monitor exists (simple logic)
    # Ideally search monitors first. For demo, we might create duplicates or fail.
    # We'll just try to create.

    payload = {
        "type": "monitor",
        "name": name,
        "enabled": True,
        "schedule": {"period": {"interval": 5, "unit": "MINUTES"}},
        "inputs": [{
            "search": {
                "indices": indices,
                "query": query_dsl
            }
        }],
        "triggers": [{
            "name": f"{name}_Trigger",
            "severity": severity,
            "condition": {
                "script": {
                    "lang": "painless",
                    "source": "ctx.results[0].hits.total.value > 0"
                }
            },
            "actions": [] # Can add slack/chime/custom webhook here
        }]
    }
    
    try:
        resp = requests.post(url, auth=AUTH, headers=HEADERS, json=payload, verify=False)
        if resp.status_code in [200, 201]:
            logger.info(f"Monitor {name} created.")
        else:
            logger.error(f"Failed to create monitor {name}: {resp.text}")
    except Exception as e:
        logger.error(f"Error creating monitor {name}: {e}")

def configure_security_analytics():
    # 1. Cloud Threat Correlation (GuardDuty + Process) -> Sev 1
    # Simple query matching either condition for now (OR logic)
    # Real correlation would use bucket aggregation.
    q_cloud_threat = {
        "size": 0,
        "query": {
            "bool": {
                "should": [
                    {"term": {"service.type": "guardduty"}},
                    {"range": {"system.process.cpu.total.pct": {"gte": 0.8}}}
                ],
                "minimum_should_match": 1,
                "filter": [
                    {"range": {"@timestamp": {"gte": "now-5m"}}}
                ]
            }
        }
    }
    create_monitor("Cloud Threat Correlation (MITRE: Execution)", ["guardduty-*", "metricbeat-*"], q_cloud_threat)

    # 2. IAM Abuse (Config + CloudTrail) -> Sev 2
    q_iam_abuse = {
        "size": 0,
        "query": {
            "bool": {
                "should": [
                   {"term": {"complianceType": "NON_COMPLIANT"}},
                   {"match": {"event.action": "ConsoleLogin"}}
                ],
                "minimum_should_match": 1,
                "filter": [
                    {"range": {"@timestamp": {"gte": "now-5m"}}}
                ]
            }
        }
    }
    create_monitor("Identity Abuse Correlation (MITRE: Persistence)", ["aws-config-*", "filebeat-*"], q_iam_abuse)

    # 3. Network Anomaly (DNS + Flow) -> Sev 3
    q_network_anomaly = {
        "size": 0,
        "query": {
            "bool": {
                "should": [
                    {"term": {"rcode": "NXDOMAIN"}},
                    {"range": {"network.bytes": {"gte": 1000000}}}
                ],
                "minimum_should_match": 1,
                "filter": [
                    {"range": {"@timestamp": {"gte": "now-5m"}}}
                ]
            }
        }
    }
    create_monitor("Network Anomaly Correlation (MITRE: Exfiltration)", ["dns-logs", "filebeat-*"], q_network_anomaly)

def create_dashboard():
    # Placeholder for Dashboard Creation using Saved Objects API
    # Creating a full dashboard JSON programmatically is verbose.
    # We will log that we would import it here.
    logger.info("Function create_dashboard() called - would import JSON dashboard object.")
    pass

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    wait_for_opensearch()
    
    # Index Patterns
    patterns = [
        "guardduty-*", "aws-config-*", "dns-logs", 
        "filebeat-*", "auditbeat-*", "metricbeat-*", 
        "wazuh-alerts-*"
    ]
    for p in patterns:
        create_index_pattern(p)
    
    # Monitors
    configure_security_analytics()
    
    # Dashboards
    create_dashboard()
    
    logger.info("OpenSearch Configuration Completed.")
