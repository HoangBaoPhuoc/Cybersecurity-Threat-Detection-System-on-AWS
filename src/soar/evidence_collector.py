import os
import json
import logging
import requests
from requests.auth import HTTPBasicAuth
from datetime import datetime, timedelta

logger = logging.getLogger()
logger.setLevel(logging.INFO)

OPENSEARCH_HOST = os.environ.get('OPENSEARCH_HOST')
OPENSEARCH_USER = "admin" # In prod use Secrets Manager
OPENSEARCH_PASS = "Admin123!" # In prod use Secrets Manager

def lambda_handler(event, context):
    """
    Queries OpenSearch for recent logs related to the entity.
    Event: {"original_event": {...}, ...}
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        payload = event.get('original_event', event)
        log = payload.get('original_log', {})
        ip = log.get('ip') or log.get('src_ip')
        user = log.get('user')
        
        if not OPENSEARCH_HOST:
            return {"evidence": "OpenSearch Config Missing"}
            
        url = f"https://{OPENSEARCH_HOST}/_search"
        auth = HTTPBasicAuth(OPENSEARCH_USER, OPENSEARCH_PASS)
        headers = {"Content-Type": "application/json"}
        
        # Build Query
        should_clauses = []
        if ip:
            should_clauses.append({"match": {"ip": ip}})
            should_clauses.append({"match": {"src_ip": ip}})
            should_clauses.append({"match": {"dst_ip": ip}})
        if user:
            should_clauses.append({"match": {"user": user}})
            
        if not should_clauses:
            return {"evidence": "No IP or User to query"}

        query = {
            "size": 10,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "should": should_clauses,
                    "minimum_should_match": 1,
                    "filter": [
                        {"range": {"@timestamp": {"gte": "now-15m"}}}
                    ]
                }
            }
        }
        
        response = requests.post(url, auth=auth, headers=headers, json=query, verify=False, timeout=5)
        
        if response.status_code == 200:
            hits = response.json()['hits']['hits']
            evidence_lines = []
            for hit in hits:
                src = hit['_source']
                ts = src.get('@timestamp', 'N/A')
                msg = src.get('message', '') or src.get('event', {}).get('action', 'Unknown Event')
                evidence_lines.append(f"[{ts}] {msg}")
            
            evidence_text = "\n".join(evidence_lines) or "No additional logs found in last 15m."
            return {"evidence": evidence_text, "hit_count": len(hits)}
        else:
            return {"evidence": f"Query Failed: {response.text}"}
            
    except Exception as e:
        logger.error(f"Evidence Collection Error: {e}")
        return {"evidence": f"Error: {str(e)}"}
