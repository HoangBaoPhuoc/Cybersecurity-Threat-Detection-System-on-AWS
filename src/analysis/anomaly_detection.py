import json
import logging
import os
import openai # Requires 'pip install openai'

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class AnomalyDetector:
    def __init__(self, model_endpoint=None, api_key=None):
        self.model_endpoint = model_endpoint
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.logger = logging.getLogger("AnomalyDetector")
        
        if self.api_key:
            openai.api_key = self.api_key

    def analyze_log(self, log_entry, context=None):
        """
        Analyze a log entry using Pure AI approach (LLM + RAG).
        Returns a confidence score (0.0 to 1.0) of being a threat.
        """
        # 1. Rule-based Analysis (DISABLED per user request)
        # rule_score = self._rule_based_score(log_entry)
        rule_score = 0.0
        # self.logger.info(f"Rule-based Score for event {log_entry.get('event_id')}: {rule_score}")

        # 2. API-based Analysis (Context-Aware RAG)
        # We now rely 100% on the LLM to detect threats based on Log + Threat Intel Context.
        ai_score = self._api_based_score(log_entry, context)
        # self.logger.info(f"AI-based Score for event {log_entry.get('timestamp')}: {ai_score}")

        return round(ai_score, 2)

    def _rule_based_score(self, log_entry):
        # Rules are disabled but kept for reference
        return 0.0

    def _api_based_score(self, log_entry, context=None):
        """
        Calls OpenAI API to analyze the log with Context-Aware Prompt.
        """
        if not self.api_key:
            self.logger.warning("No API Key found. Skipping AI analysis.")
            return 0.0
        
        # Construct RAG Prompt
        threat_context_str = json.dumps(context) if context else "No Threat Intelligence Found."
        
        system_prompt = """
        You are an expert Cybersecurity AI Analyst. 
        Your task is to detect anomalies, security threats, and suspicious behaviors in system logs.
        
        Analyze the provided Log Entry and Threat Intelligence Context.
        Focus on identifying ANY behavior that deviates from a secure baseline, such as:
        - Unauthorized access attempts or privilege escalation.
        - Unusual data movement or exfiltration.
        - System integrity violations (unexpected file modifications).
        - Abnormal resource usage patterns (potential DoS or crypto-mining).
        - Execution of suspicious commands or connections to malicious IPs.
        - Logic flaws or business process abuse.
        
        Use the Threat Context to validate known malicious indicators.
        
        Output valid JSON only:
        {
            "risk_score": <float 0.0-1.0>,
            "reasoning": "<concise explanation of the anomaly or threat>"
        }
        """
        
        user_prompt = f"""
        Log Entry: {json.dumps(log_entry)}
        Threat Context: {threat_context_str}
        """
        
        try:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo", # Or gpt-4
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1
            )
            
            content = response.choices[0].message.content.strip()
            result = json.loads(content)
            
            score = result.get('risk_score', 0.0)
            reason = result.get('reasoning', "No reasoning provided")
            
            if score > 0.5:
                self.logger.info(f"LLM Reasoning: {reason}")
                
            return score

        except Exception as e:
            self.logger.error(f"AI Analysis failed: {e}")
            return 0.0

# ThreatEnricher has been moved to src/analysis/threat_intel.py
# process_stream has been moved to src/analysis/detection_runner.py

if __name__ == "__main__":
    # Simple test for AnomalyDetector
    detector = AnomalyDetector()
    test_log = {"event_id": "test", "status": "FAILURE", "user": "root"}
    print(f"Test Score: {detector.analyze_log(test_log)}")

