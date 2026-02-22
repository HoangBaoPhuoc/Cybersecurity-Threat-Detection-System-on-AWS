"""
LLM Explainer for Security Alerts
==================================

This module uses LLM (GPT/Claude) to EXPLAIN security alerts and anomalies
detected by ML models. It does NOT analyze raw logs directly.

The LLM receives:
- Alert summary
- Feature values that triggered the alert
- ML model scores
- Context from threat intelligence

And generates:
- Human-readable explanation
- Recommended actions
- Risk assessment justification

This aligns with best practices:
- ML/DL for detection (fast, scalable, real-time)
- LLM for explanation (interpretability, actionable insights)
"""

import logging
import json
import os

import boto3

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("LLMExplainer")


class LLMExplainer:
    """
    LLM-based explainer for ML-detected anomalies.
    """
    
    def __init__(self, model=None):
        self.model = model or os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet-20240229-v1:0")
        self.client = boto3.client("bedrock-runtime")
    
    def explain_alert(self, alert_data):
        """
        Generate human-readable explanation for an ML-detected alert.
        
        Args:
            alert_data (dict): {
                "log_summary": {...},  # Basic log info (not full raw log)
                "features": {...},     # Feature values that triggered detection
                "ml_scores": {...},    # Scores from ML models
                "threat_context": {...} # Threat intelligence context
            }
        
        Returns:
            dict: {
                "explanation": str,
                "recommended_actions": list,
                "confidence": float
            }
        """
        try:
            system_prompt = """
You are a Senior Security Analyst AI Assistant specializing in explaining anomaly detection alerts.

Your task is to:
1. Analyze the ML-detected anomaly based on feature values and model scores
2. Provide a clear, concise explanation of WHY this is anomalous
3. Recommend specific next actions for the SOC team
4. Assess the confidence/severity of this alert

Focus on:
- Feature patterns that indicate threats (e.g., high failed login count, unusual time access)
- Contextual factors (privileged user, threat intel matches)
- Business impact and urgency

Output valid JSON:
{
    "explanation": "<2-3 sentence explanation of the anomaly>",
    "key_indicators": ["<indicator 1>", "<indicator 2>", ...],
    "recommended_actions": ["<action 1>", "<action 2>", ...],
    "severity_justification": "<why this severity level>",
    "confidence": <float 0.0-1.0>
}
"""
            
            user_prompt = self._build_prompt(alert_data)

            payload = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 500,
                "temperature": 0.2,
                "messages": [
                    {"role": "user", "content": f"{system_prompt}\n\n{user_prompt}"}
                ]
            }

            response = self.client.invoke_model(modelId=self.model, body=json.dumps(payload))
            body = json.loads(response["body"].read())
            content = body.get("content", [])
            text = content[0].get("text", "") if content else body.get("completion", "")
            result = json.loads(text)
            
            logger.info(f"LLM Explanation generated: {result.get('explanation', '')[:100]}...")
            
            return result
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response: {e}")
            return self._mock_explanation(alert_data)
        except Exception as e:
            logger.error(f"LLM API call failed: {e}")
            return self._mock_explanation(alert_data)
    
    def _build_prompt(self, alert_data):
        """Build structured prompt from alert data"""
        
        log_summary = alert_data.get("log_summary", {})
        features = alert_data.get("features", {})
        ml_scores = alert_data.get("ml_scores", {})
        threat_context = alert_data.get("threat_context", {})
        
        # Extract key features for explanation
        key_features = {
            "User": log_summary.get("user", "unknown"),
            "Source IP": log_summary.get("src_ip", "unknown"),
            "Event Type": log_summary.get("event_type", "unknown"),
            "Status": log_summary.get("status", "unknown"),
            "Timestamp": log_summary.get("timestamp", "unknown")
        }
        
        # Extract important feature values
        important_features = {}
        high_risk_features = [
            'user_failed_event_count',
            'ip_failed_count',
            'is_privileged_user',
            'threat_intel_malicious_ip',
            'recent_fail_sequence_length',
            'user_unique_ip_count'
        ]
        
        for feat in high_risk_features:
            if feat in features:
                important_features[feat] = features[feat]
        
        prompt = f"""
# Security Alert Analysis Request

## Event Summary
{json.dumps(key_features, indent=2)}

## ML Detection Scores
{json.dumps(ml_scores, indent=2)}

## Key Feature Values (that triggered detection)
{json.dumps(important_features, indent=2)}

## Threat Intelligence Context
{json.dumps(threat_context, indent=2) if threat_context else "No threat intel data available"}

---

Please analyze this ML-detected anomaly and provide explanation.
"""
        return prompt
    
    def _mock_explanation(self, alert_data):
        """Fallback explanation when LLM is not available"""
        ml_scores = alert_data.get("ml_scores", {})
        features = alert_data.get("features", {})
        
        # Simple rule-based explanation
        indicators = []
        
        if features.get('user_failed_event_count', 0) > 5:
            indicators.append(f"High failed login count ({features['user_failed_event_count']})")
        
        if features.get('is_privileged_user', 0) == 1.0:
            indicators.append("Activity from privileged account")
        
        if features.get('threat_intel_malicious_ip', 0) == 1.0:
            indicators.append("Connection from known malicious IP")
        
        if features.get('recent_fail_sequence_length', 0) > 3:
            indicators.append(f"Rapid failure sequence ({features['recent_fail_sequence_length']} in 5 min)")
        
        ensemble_score = ml_scores.get('ensemble_score', 0)
        
        explanation = f"ML models detected anomalous behavior with confidence {ensemble_score:.2f}. "
        if indicators:
            explanation += "Key indicators: " + ", ".join(indicators)
        else:
            explanation += "Deviation from normal baseline patterns detected."
        
        return {
            "explanation": explanation,
            "key_indicators": indicators,
            "recommended_actions": [
                "Review user activity logs",
                "Check for unauthorized access attempts",
                "Verify user identity if suspicious"
            ],
            "severity_justification": f"Based on ML score {ensemble_score:.2f} and detected patterns",
            "confidence": min(ensemble_score, 0.9)
        }
    
    def explain_investigation_query(self, query, context):
        """
        Answer analyst questions about alerts/incidents using LLM.
        
        Args:
            query (str): Analyst's question
            context (dict): Relevant context (alerts, logs, etc.)
        
        Returns:
            str: LLM-generated answer
        """
        try:
            system_prompt = """
You are a Security Operations Center (SOC) AI Assistant.
Help analysts understand security alerts and recommend investigation steps.
Provide clear, actionable guidance based on the context provided.
"""
            
            user_prompt = f"""
Context: {json.dumps(context, indent=2)}

Analyst Question: {query}

Please provide a helpful answer based on the context.
"""
            
            payload = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 300,
                "temperature": 0.3,
                "messages": [
                    {"role": "user", "content": f"{system_prompt}\n\n{user_prompt}"}
                ]
            }

            response = self.client.invoke_model(modelId=self.model, body=json.dumps(payload))
            body = json.loads(response["body"].read())
            content = body.get("content", [])
            return content[0].get("text", "") if content else body.get("completion", "")
            
        except Exception as e:
            logger.error(f"Investigation query failed: {e}")
            return f"Error processing query: {str(e)}"


if __name__ == "__main__":
    # Test LLM Explainer
    explainer = LLMExplainer()
    
    test_alert = {
        "log_summary": {
            "user": "root",
            "src_ip": "192.168.1.100",
            "event_type": "Failed Login",
            "status": "FAILURE",
            "timestamp": "2026-02-21T10:30:00Z"
        },
        "features": {
            "user_failed_event_count": 15,
            "ip_failed_count": 20,
            "is_privileged_user": 1.0,
            "threat_intel_malicious_ip": 0.0,
            "recent_fail_sequence_length": 8,
            "user_unique_ip_count": 1
        },
        "ml_scores": {
            "ensemble_score": 0.85,
            "isolation_forest_score": 0.82,
            "autoencoder_score": 0.88
        },
        "threat_context": None
    }
    
    explanation = explainer.explain_alert(test_alert)
    print("\n=== Alert Explanation ===")
    print(json.dumps(explanation, indent=2))
