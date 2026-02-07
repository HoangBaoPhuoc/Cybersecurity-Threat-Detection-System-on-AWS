import time
import json
import logging
import os
from datetime import datetime, timedelta

try:
    from opensearchpy import OpenSearch, RequestsHttpConnection
except ImportError:
    OpenSearch = None

from anomaly_detection import AnomalyDetector
from rag_engine import ThreatIntelRAG
from alert_manager import AlertManager

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("AIOrchestrator")

# Configuration
OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", 9200))
OPENSEARCH_AUTH = (os.getenv("OPENSEARCH_USER", "admin"), os.getenv("OPENSEARCH_PASS", "Admin123!"))
INDEX_PATTERN = "logs-*,audit-logs-*,metrics-system-*" # Monitor all indices

def get_opensearch_client():
    if not OpenSearch:
        logger.warning("opensearch-py not installed. Using Mock Data Mode.")
        return None
    
    try:
        client = OpenSearch(
            hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
            http_auth=OPENSEARCH_AUTH,
            use_ssl=True,
            verify_certs=False,
            connection_class=RequestsHttpConnection
        )
        return client
    except Exception as e:
        logger.error(f"Failed to connect to OpenSearch: {e}")
        return None

def fetch_new_logs(client, last_poll_time):
    """
    Query OpenSearch for logs newer than last_poll_time.
    """
    if not client:
        # Mock Data Generator
        yield {"event_id": "1001", "timestamp": datetime.now().isoformat(), "status": "SUCCESS", "user": "alice", "ip": "10.0.0.5"}
        if int(time.time()) % 10 == 0: # Every 10 seconds mock a failure
            yield {"event_id": "1002", "timestamp": datetime.now().isoformat(), "status": "FAILURE", "user": "root", "ip": "192.168.1.5", "message": "Failed password for root"}
        return

    query = {
        "query": {
            "range": {
                "@timestamp": {
                    "gt": last_poll_time.isoformat()
                }
            }
        },
        "sort": [{"@timestamp": {"order": "asc"}}],
        "size": 100
    }

    try:
        response = client.search(body=query, index=INDEX_PATTERN)
        hits = response['hits']['hits']
        logger.info(f"Fetched {len(hits)} new logs from OpenSearch.")
        for hit in hits:
            yield hit['_source']
    except Exception as e:
        logger.error(f"Error querying OpenSearch: {e}")

def run_detection_loop():
    logger.info("Starting AI Orchestrator...")
    
    # Initialize Modules
    client = get_opensearch_client()
    detector = AnomalyDetector()
    rag_engine = ThreatIntelRAG(mcp_url="http://localhost:8000")
    alert_manager = AlertManager(step_function_arn="arn:aws:states:us-east-1:123456789012:stateMachine:threat-response-workflow")

    last_poll_time = datetime.now() - timedelta(minutes=1)

    while True:
        current_time = datetime.now()
        
        for log_entry in fetch_new_logs(client, last_poll_time):
            # 0. Pre-Fetch Context (Threat Intel)
            ip = log_entry.get('ip') or log_entry.get('src_ip')
            threat_context = None
            if ip:
                threat_context = rag_engine.lookup_ip(ip)

            # 1. AI Analysis (with Context)
            score = detector.analyze_log(log_entry, context=threat_context)
            
            # 2. Threshold Check
            if score >= 0.4:
                logger.warning(f"Suspicious Activity Detected (Score: {score})")
                
                # 3. Threat Intel Enrichment (Full RAG)
                # We can reuse the context we already fetched to avoid double lookup if we want, 
                # but for now let's keep the flow simple or pass it in.
                alert_payload = {"original_log": log_entry, "score": score}
                enriched_alert = rag_engine.enrich_alert(alert_payload, existing_context=threat_context)
                
                # 4. Alert Dispatch (SOAR)
                alert_manager.dispatch_alert(enriched_alert)
                
                print(f"[ALERT DISPATCHED] {json.dumps(enriched_alert, indent=2)}\n")

        last_poll_time = current_time
        time.sleep(10) # Poll every 10 seconds

if __name__ == "__main__":
    run_detection_loop()
