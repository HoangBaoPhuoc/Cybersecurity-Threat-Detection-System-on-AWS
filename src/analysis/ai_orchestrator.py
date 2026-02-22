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

GUARDDUTY_SEVERITY_THRESHOLDS = [
    (8.9, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.0, "LOW")
]

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


def _map_guardduty_severity(value):
    try:
        severity_value = float(value)
    except (TypeError, ValueError):
        return None

    for threshold, label in GUARDDUTY_SEVERITY_THRESHOLDS:
        if severity_value >= threshold:
            return label
    return "LOW"


def _map_securityhub_severity(detail):
    findings = detail.get("findings") if isinstance(detail, dict) else None
    if not findings:
        return None

    finding = findings[0]
    severity = finding.get("Severity", {})
    label = severity.get("Label")
    if label:
        return str(label).upper()

    normalized = severity.get("Normalized")
    if normalized is None:
        return None

    try:
        normalized_value = float(normalized)
    except (TypeError, ValueError):
        return None

    if normalized_value >= 90:
        return "CRITICAL"
    if normalized_value >= 70:
        return "HIGH"
    if normalized_value >= 40:
        return "MEDIUM"
    return "LOW"


def _extract_event_severity(log_entry):
    if not isinstance(log_entry, dict):
        return None

    if "severity" in log_entry and isinstance(log_entry.get("severity"), str):
        return log_entry.get("severity").upper()

    detail = log_entry.get("detail", {})
    securityhub = _map_securityhub_severity(detail)
    if securityhub:
        return securityhub

    guardduty_value = detail.get("severity") if isinstance(detail, dict) else None
    guardduty = _map_guardduty_severity(guardduty_value)
    if guardduty:
        return guardduty

    return None

def run_detection_loop():
    logger.info("Starting AI Orchestrator with Hybrid Detection (Rule + ML)...")
    
    # Initialize Modules
    client = get_opensearch_client()
    detector = AnomalyDetector()  # Now uses ML models
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

            # 1. ML-Based Anomaly Detection (NEW APPROACH)
            # Returns: (anomaly_score, features, ml_details)
            anomaly_score, features, ml_details = detector.analyze_log(log_entry, context=threat_context)
            
            # 2. Risk Engine Update (Stateful)
            entity_id = f"user:{user}" if user else f"ip:{ip}"
            
            if anomaly_score > 0.0:
                severity = _extract_event_severity(log_entry)
                if not severity:
                    if anomaly_score >= 0.8:
                        severity = "CRITICAL"
                    elif anomaly_score >= 0.6:
                        severity = "HIGH"
                    elif anomaly_score >= 0.3:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"

                context = {
                    "untrusted_ip": threat_context is not None and threat_context.get("risk") == "HIGH",
                    "admin_role": bool(user and user.lower() in ["root", "admin", "administrator"]),
                    "geo_anomaly": log_entry.get("geo_anomaly", False)
                }

                risk_update = risk_engine.update_risk(entity_id, {
                    "severity": severity,
                    "context": context
                })

                current_risk_score = risk_update["risk_score"]
                logger.info(f"Entity {entity_id} Risk: {current_risk_score}")
            else:
                current_risk_score = 0.0

            # 3. Decision Logic (Stateful OR Instantaneous)
            # Trigger if Anomaly is high OR Cumulative Risk is high
            if anomaly_score >= 0.7 or current_risk_score >= 40:
                logger.warning(f"ACTION TRIGGERED | Anomaly: {anomaly_score} | Risk: {current_risk_score}")

                alert_payload = {
                    "alert_id": log_entry.get("event_id", "unknown"),
                    "timestamp": log_entry.get("timestamp", datetime.now().isoformat()),
                    "detection_method": "ML-based Anomaly Detection",
                    "models_used": ml_details.get("models_used", ["Hybrid"]),
                    "original_log": log_entry,
                    "anomaly_score": anomaly_score,
                    "ml_details": ml_details,
                    "extracted_features": features,
                    "risk_state": {
                        "score": current_risk_score
                    },
                    "threat_intel": threat_context
                }

                enriched_alert = rag_engine.enrich_alert(alert_payload, existing_context=threat_context)
                alert_manager.dispatch_alert(enriched_alert)

        last_poll_time = current_time
        time.sleep(10) # Poll every 10 seconds

if __name__ == "__main__":
    run_detection_loop()
