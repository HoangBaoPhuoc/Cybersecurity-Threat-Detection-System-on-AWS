import requests
import logging

class ThreatIntelRAG:
    def __init__(self, mcp_url="http://localhost:8000"):
        self.mcp_url = mcp_url
        self.logger = logging.getLogger("ThreatIntelRAG")
        
    def lookup_ip(self, ip):
        """
        Query MCP Server for IP Reputation.
        """
        try:
            response = requests.get(f"{self.mcp_url}/ip/{ip}", timeout=2)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            self.logger.warning(f"Failed to call MCP for IP lookup: {e}")
        return None

    def enrich_alert(self, alert_data, existing_context=None):
        """
        Enrich an alert using external MCP tools and internal knowledge.
        """
        original_log = alert_data.get('original_log', {})
        enrichment = {
            "threat_intel_source": "MCP + Internal RAG",
            "mitre_technique": "T1078 - Valid Accounts", # Default, would be dynamic in real RAG
            "risk_score": alert_data.get('score', 0.0)
        }
        
        # 1. IP Reputation Lookup (or use existing context)
        ip = original_log.get('ip') or original_log.get('src_ip')
        ip_data = existing_context
        
        if ip and not ip_data:
            ip_data = self.lookup_ip(ip)

        if ip_data:
            enrichment['ip_reputation'] = ip_data
            if ip_data.get('risk') == 'HIGH':
                enrichment['risk_score'] = min(enrichment['risk_score'] + 0.2, 1.0)

        # 2. Add Recommended Action based on Severity
        if enrichment['risk_score'] >= 0.8:
            enrichment['severity'] = "CRITICAL"
            enrichment['suggested_action'] = "Block IP and Isolate Host immediately."
        elif enrichment['risk_score'] >= 0.5:
            enrichment['severity'] = "HIGH"
            enrichment['suggested_action'] = "Reset User Password and Monitor."
        else:
            enrichment['severity'] = "MEDIUM"
            enrichment['suggested_action'] = "Log and Observe."

        return {**alert_data, **enrichment}
