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
from risk_engine import EntityRiskEngine

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
        yield {"event_id": "1001", "timestamp": datetime.now().isoformat(), "status": "SUCCESS", "user": "alice", "ip": "10.0.0.5", "event_type": "Login"}
        if int(time.time()) % 10 == 0: # Every 10 seconds mock a failure
            yield {
                "event_id": "1002", 
                "timestamp": datetime.now().isoformat(), 
                "status": "FAILURE", 
                "user": "root", 
                "ip": "192.168.1.5", 
                "event_type": "Failed Login",
                "message": "Failed password for root"
            }
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
    mcp_url = os.getenv("MCP_URL", "http://localhost:8000")
    rag_engine = ThreatIntelRAG(mcp_url=mcp_url)
    risk_engine = EntityRiskEngine()
    
    sfn_arn = os.getenv("STEP_FUNCTION_ARN", "arn:aws:states:us-east-1:123456789012:stateMachine:threat-response-workflow")
    alert_manager = AlertManager(step_function_arn=sfn_arn)

    last_poll_time = datetime.now() - timedelta(minutes=1)

    while True:
        current_time = datetime.now()
        
        for log_entry in fetch_new_logs(client, last_poll_time):
            # 0. Pre-Fetch Context (Threat Intel)
            ip = log_entry.get('ip') or log_entry.get('src_ip')
            user = log_entry.get('user')
            
            threat_context = None
            if ip:
                threat_context = rag_engine.lookup_ip(ip)

            # 1. AI Analysis (with Context)
            anomaly_score = detector.analyze_log(log_entry, context=threat_context)
            
            # 2. Risk Engine Update (Stateful)
            entity_id = f"user:{user}" if user else f"ip:{ip}"
            
            if anomaly_score > 0.0:
                # Calculate multipliers based on context
                # Asset Criticality (simulated based on IP/Host)
                asset_criticality = "low"
                if log_entry.get('dst_ip') == "10.0.0.5": # Core Banking
                    asset_criticality = "critical"

                # Update Risk State
                risk_update = risk_engine.update_risk(entity_id, {
                    "alert_id": log_entry.get("event_id"),
                    "type": log_entry.get("event_type", "Unknown Anomaly"),
                    "anomaly_confidence": anomaly_score,
                    "asset_criticality": asset_criticality,
                    "multipliers": {} 
                })
                
                # Check for skipped score (idempotency)
                if risk_update.get("skipped"):
                     logger.info(f"Skipping risk update for {entity_id} - Duplicate Alert")

                current_risk_score = risk_update["risk_score"]
                current_risk_level = risk_update["risk_level"]
                
                logger.info(f"Entity {entity_id} Risk: {current_risk_score} ({current_risk_level})")
            else:
                current_risk_score = 0
                current_risk_level = "LOW"

            # 3. Decision Logic (Stateful OR Instantaneous)
            # Trigger if Anomaly is high OR Cumulative Risk is high
            if anomaly_score >= 0.7 or current_risk_score >= 40:
                logger.warning(f"ACTION TRIGGERED | Anomaly: {anomaly_score} | Risk: {current_risk_score}")
                
                # 4. Threat Intel Enrichment (Full RAG)
                alert_payload = {
                    "original_log": log_entry, 
                    "score": anomaly_score,
                    "risk_state": {
                        "score": current_risk_score,
                        "level": current_risk_level
                    }
                }
                enriched_alert = rag_engine.enrich_alert(alert_payload, existing_context=threat_context)
                
                # 5. Alert Dispatch (SOAR)
                # Override severity based on Risk Level if it's higher
                if current_risk_score >= 90:
                    enriched_alert["severity"] = "CRITICAL"
                elif current_risk_score >= 70:
                    enriched_alert["severity"] = "HIGH"
                
                alert_manager.dispatch_alert(enriched_alert)
                
                print(f"[ALERT DISPATCHED] {json.dumps(enriched_alert, indent=2)}\n")

        last_poll_time = current_time
        time.sleep(10) # Poll every 10 seconds

if __name__ == "__main__":
    run_detection_loop()
