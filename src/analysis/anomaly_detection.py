"""
Hybrid Anomaly Detection Engine
================================

This module implements a hybrid detection approach combining:
1. Rule-based detection (Wazuh rules - handled externally)
2. ML-based anomaly detection (Isolation Forest, Autoencoder)
3. Feature engineering for security logs

The ML models detect deviations from normal behavior patterns.
LLM is NOT used here - explanation happens in llm_explainer.py

Architecture:
    Log → Feature Extraction → ML Models → Anomaly Score
"""

import json
import logging
import os

from feature_extractor import FeatureExtractor
from ml_models import MLAnomalyDetector, LSTMSequenceDetector

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class AnomalyDetector:
    """
    Hybrid Anomaly Detector using ML models on extracted features.
    Does NOT use LLM for detection (only for explanation later).
    """
    
    def __init__(self, model_dir="models"):
        self.logger = logging.getLogger("AnomalyDetector")
        
        # Initialize feature extractor
        self.feature_extractor = FeatureExtractor(window_size_minutes=60)
        
        # Initialize ML models
        self.ml_detector = MLAnomalyDetector(model_dir=model_dir)
        self.lstm_detector = LSTMSequenceDetector(model_dir=model_dir)
        
        # Check if models are trained
        if not self.ml_detector.is_trained:
            self.logger.warning("ML models not trained. Running in baseline collection mode.")
            self.logger.info("To train models, collect normal traffic and run: python train_models.py")

    def analyze_log(self, log_entry, context=None):
        """
        Analyze a log entry using ML-based anomaly detection.
        
        Args:
            log_entry (dict): Log event to analyze
            context (dict): Threat intelligence context (optional)
        
        Returns:
            tuple: (anomaly_score, feature_dict, ml_details)
                - anomaly_score (float): 0.0 to 1.0
                - feature_dict (dict): Extracted features
                - ml_details (dict): Detailed scores from each model
        """
        
        # Step 1: Extract features from log
        features = self.feature_extractor.extract_features(log_entry, threat_context=context)
        feature_vector = self.feature_extractor.get_feature_vector(log_entry, threat_context=context)
        
        # Step 2: ML-based detection
        if self.ml_detector.is_trained:
            ml_result = self.ml_detector.predict(feature_vector, return_details=True)
            anomaly_score = ml_result['ensemble_score']
            
            # Optional: Add LSTM sequence detection
            lstm_score = self.lstm_detector.predict(feature_vector)
            
            # Combine scores (weighted)
            if lstm_score > 0:
                combined_score = 0.7 * anomaly_score + 0.3 * lstm_score
                ml_result['lstm_score'] = lstm_score
                ml_result['combined_score'] = combined_score
                anomaly_score = combined_score
            
            if anomaly_score > 0.5:
                self.logger.info(f"Anomaly detected: {anomaly_score:.2f} for user {log_entry.get('user')}")
        else:
            # Fallback: Simple rule-based heuristics during training phase
            anomaly_score = self._simple_heuristic(features, context)
            ml_result = {
                "ensemble_score": anomaly_score,
                "note": "Using heuristics - ML models not trained yet"
            }
        
        return round(anomaly_score, 2), features, ml_result
    
    def _simple_heuristic(self, features, context=None):
        """
        Simple rule-based heuristic for when ML models aren't trained yet.
        """
        score = 0.0
        
        # High failed login count
        if features.get('user_failed_event_count', 0) > 5:
            score += 0.3
        
        # Privileged user with failures
        if features.get('is_privileged_user', 0) == 1.0 and features.get('is_failed_event', 0) == 1.0:
            score += 0.4
        
        # Threat intel match
        if features.get('threat_intel_malicious_ip', 0) == 1.0:
            score += 0.5
        
        # Rapid failure sequence
        if features.get('recent_fail_sequence_length', 0) > 5:
            score += 0.3
        
        # Many unique IPs for one user (lateral movement)
        if features.get('user_unique_ip_count', 0) > 10:
            score += 0.2
        
        return min(score, 1.0)


if __name__ == "__main__":
    # Test the new hybrid anomaly detector
    print("=== Testing Hybrid Anomaly Detector ===\n")
    
    detector = AnomalyDetector()
    
    # Test logs
    test_logs = [
        {
            "timestamp": "2026-02-21T10:30:00Z",
            "user": "alice",
            "ip": "10.0.0.1",
            "event_type": "Login",
            "status": "SUCCESS"
        },
        {
            "timestamp": "2026-02-21T10:31:00Z",
            "user": "root",
            "ip": "192.168.1.100",
            "event_type": "Failed Login",
            "status": "FAILURE"
        },
        {
            "timestamp": "2026-02-21T10:31:30Z",
            "user": "root",
            "ip": "192.168.1.100",
            "event_type": "Failed Login",
            "status": "FAILURE"
        },
        {
            "timestamp": "2026-02-21T10:32:00Z",
            "user": "root",
            "ip": "192.168.1.100",
            "event_type": "Failed Login",
            "status": "FAILURE"
        }
    ]
    
    print("Processing test logs...\n")
    for i, log in enumerate(test_logs):
        score, features, ml_details = detector.analyze_log(log)
        print(f"Log {i+1}: {log['user']} - {log['event_type']}")
        print(f"  Anomaly Score: {score}")
        print(f"  Key Features:")
        print(f"    - Failed events: {features.get('user_failed_event_count', 0)}")
        print(f"    - Privileged user: {features.get('is_privileged_user', 0)}")
        print(f"    - Recent failures: {features.get('recent_fail_sequence_length', 0)}")
        print(f"  ML Details: {ml_details}")
        print()

