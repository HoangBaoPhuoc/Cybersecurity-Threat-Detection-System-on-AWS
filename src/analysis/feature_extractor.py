"""
Feature Extractor for Cybersecurity Log Analysis
=================================================

This module extracts numeric and categorical features from security logs
to prepare them for ML/DL anomaly detection models.

Feature Categories:
- Event Frequency Features (count-based)
- Time-based Features (temporal patterns)
- Statistical Features (distribution, entropy)
- Sequence Features (pattern matching)
- Context Features (enrichment from threat intel)

References:
- Ahmed, M., Mahmood, A. N., & Hu, J. (2016). A survey of network anomaly detection techniques.
- Chandola, V., Banerjee, A., & Kumar, V. (2009). Anomaly detection: A survey.
"""

import logging
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import math
import numpy as np

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("FeatureExtractor")


class FeatureExtractor:
    """
    Extract features from security logs for ML-based anomaly detection.
    Maintains a sliding window of historical events for temporal features.
    """
    
    def __init__(self, window_size_minutes=60):
        self.window_size = timedelta(minutes=window_size_minutes)
        self.event_history = []  # [(timestamp, event_dict)]
        self.user_activity = defaultdict(list)  # user -> [(timestamp, event_type)]
        self.ip_activity = defaultdict(list)  # ip -> [(timestamp, event_type)]
        
    def _clean_old_events(self, current_time):
        """Remove events outside the sliding window"""
        cutoff_time = current_time - self.window_size
        
        # Clean global history
        self.event_history = [(ts, evt) for ts, evt in self.event_history if ts > cutoff_time]
        
        # Clean user activity
        for user in list(self.user_activity.keys()):
            self.user_activity[user] = [(ts, evt) for ts, evt in self.user_activity[user] if ts > cutoff_time]
            if not self.user_activity[user]:
                del self.user_activity[user]
        
        # Clean IP activity
        for ip in list(self.ip_activity.keys()):
            self.ip_activity[ip] = [(ts, evt) for ts, evt in self.ip_activity[ip] if ts > cutoff_time]
            if not self.ip_activity[ip]:
                del self.ip_activity[ip]
    
    def _parse_timestamp(self, log_entry):
        """Parse timestamp from log entry"""
        ts_str = log_entry.get('timestamp') or log_entry.get('@timestamp')
        if not ts_str:
            return datetime.now()
        
        try:
            # Handle ISO format
            if 'T' in ts_str:
                return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            return datetime.fromisoformat(ts_str)
        except:
            return datetime.now()
    
    def _calculate_entropy(self, items):
        """Calculate Shannon entropy of a list of items"""
        if not items:
            return 0.0
        
        counts = Counter(items)
        total = len(items)
        entropy = 0.0
        
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def extract_features(self, log_entry, threat_context=None):
        """
        Extract comprehensive feature vector from a log entry.
        
        Returns:
            dict: Feature dictionary with numeric values suitable for ML models
        """
        current_time = self._parse_timestamp(log_entry)
        self._clean_old_events(current_time)
        
        # Extract basic fields
        user = log_entry.get('user', 'unknown')
        src_ip = log_entry.get('ip') or log_entry.get('src_ip', 'unknown')
        dst_ip = log_entry.get('dst_ip', 'unknown')
        event_type = log_entry.get('event_type', 'unknown')
        status = log_entry.get('status', 'unknown')
        
        features = {}
        
        # ==========================================
        # A. EVENT FREQUENCY FEATURES (Count-based)
        # ==========================================
        
        # Failed event count for this user (time window)
        user_events = self.user_activity.get(user, [])
        features['user_failed_event_count'] = sum(1 for _, evt in user_events if 'fail' in evt.lower())
        features['user_total_event_count'] = len(user_events)
        features['user_success_rate'] = (
            (features['user_total_event_count'] - features['user_failed_event_count']) / max(features['user_total_event_count'], 1)
        )
        
        # IP-based event counts
        ip_events = self.ip_activity.get(src_ip, [])
        features['ip_event_count'] = len(ip_events)
        features['ip_failed_count'] = sum(1 for _, evt in ip_events if 'fail' in evt.lower())
        
        # Unique IP count for this user (lateral movement indicator)
        # Extract IPs from event history for this user
        user_ips = set()
        for u, events in self.user_activity.items():
            if u == user:
                # Would need IP tracking per event - simplified for now
                pass
        features['user_unique_ip_count'] = len(user_ips) if user_ips else 1
        
        # Unique users from this IP (shared credential indicator)
        ip_users = set()
        for evt_user, events in self.user_activity.items():
            if any(src_ip in str(evt) for _, evt in events):
                ip_users.add(evt_user)
        features['ip_unique_user_count'] = len(ip_users)
        
        # Event type diversity
        event_types_in_window = [evt for _, evt in self.event_history]
        features['event_type_entropy'] = self._calculate_entropy(event_types_in_window)
        
        # Current event is failure
        features['is_failed_event'] = 1.0 if 'fail' in status.lower() else 0.0
        
        # ==========================================
        # B. TIME-BASED FEATURES (Temporal)
        # ==========================================
        
        # Time since last event for this user
        if user_events:
            last_event_time = max(ts for ts, _ in user_events)
            features['time_since_last_user_event_seconds'] = (current_time - last_event_time).total_seconds()
        else:
            features['time_since_last_user_event_seconds'] = 0.0
        
        # Event rate (events per minute)
        if self.event_history:
            time_span = (current_time - min(ts for ts, _ in self.event_history)).total_seconds() / 60.0
            features['global_event_rate'] = len(self.event_history) / max(time_span, 1.0)
        else:
            features['global_event_rate'] = 0.0
        
        # Hour of day (0-23) - encoding as sin/cos for cyclical nature
        hour = current_time.hour
        features['hour_sin'] = math.sin(2 * math.pi * hour / 24)
        features['hour_cos'] = math.cos(2 * math.pi * hour / 24)
        
        # Day of week (0-6)
        day = current_time.weekday()
        features['day_sin'] = math.sin(2 * math.pi * day / 7)
        features['day_cos'] = math.cos(2 * math.pi * day / 7)
        
        # ==========================================
        # C. STATISTICAL FEATURES (Distribution)
        # ==========================================
        
        # Inter-event time statistics for user
        if len(user_events) >= 2:
            sorted_times = sorted([ts for ts, _ in user_events])
            inter_event_times = [(sorted_times[i+1] - sorted_times[i]).total_seconds() 
                                 for i in range(len(sorted_times)-1)]
            features['user_inter_event_mean'] = np.mean(inter_event_times)
            features['user_inter_event_std'] = np.std(inter_event_times)
        else:
            features['user_inter_event_mean'] = 0.0
            features['user_inter_event_std'] = 0.0
        
        # IP entropy (how many different IPs in window)
        # Extract IPs from stored event history
        all_ips = []
        for ts, evt in self.event_history:
            if isinstance(evt, dict):
                ip_val = evt.get('ip') or evt.get('src_ip', 'unknown')
                all_ips.append(ip_val)
        features['ip_entropy'] = self._calculate_entropy(all_ips)
        
        # User entropy
        all_users = [u for u, _ in self.user_activity.items() for _ in range(len(self.user_activity[u]))]
        features['user_entropy'] = self._calculate_entropy(all_users)
        
        # ==========================================
        # D. CATEGORICAL ENCODING (One-hot style)
        # ==========================================
        
        # Privileged user flag
        privileged_users = ['root', 'admin', 'administrator', 'system', 'sudo']
        features['is_privileged_user'] = 1.0 if user.lower() in privileged_users else 0.0
        
        # Event type encoding (simplified)
        event_type_map = {
            'login': 1.0,
            'logout': 2.0,
            'file_access': 3.0,
            'network_connection': 4.0,
            'process_start': 5.0,
            'failed login': 6.0,
            'authentication': 7.0
        }
        features['event_type_code'] = event_type_map.get(event_type.lower(), 0.0)
        
        # ==========================================
        # E. CONTEXT FEATURES (Threat Intelligence)
        # ==========================================
        
        if threat_context:
            features['threat_intel_malicious_ip'] = 1.0 if threat_context.get('is_malicious') else 0.0
            features['threat_intel_confidence'] = float(threat_context.get('confidence', 0.0))
            features['threat_intel_reputation_score'] = float(threat_context.get('reputation_score', 50.0)) / 100.0
        else:
            features['threat_intel_malicious_ip'] = 0.0
            features['threat_intel_confidence'] = 0.0
            features['threat_intel_reputation_score'] = 0.5
        
        # ==========================================
        # F. SEQUENCE FEATURES (Simple Pattern)
        # ==========================================
        
        # Check for rapid repeated failures (brute force indicator)
        recent_user_events = [evt for ts, evt in user_events if (current_time - ts).total_seconds() < 300]  # 5 min
        features['recent_fail_sequence_length'] = sum(1 for evt in recent_user_events if 'fail' in evt.lower())
        
        # Update history
        self.event_history.append((current_time, log_entry))
        self.user_activity[user].append((current_time, event_type))
        self.ip_activity[src_ip].append((current_time, event_type))
        
        return features
    
    def get_feature_vector(self, log_entry, threat_context=None):
        """
        Extract features and return as numpy array (for sklearn models).
        
        Returns:
            np.ndarray: Feature vector
        """
        features = self.extract_features(log_entry, threat_context)
        
        # Define consistent feature order
        feature_names = [
            'user_failed_event_count', 'user_total_event_count', 'user_success_rate',
            'ip_event_count', 'ip_failed_count', 'user_unique_ip_count', 
            'ip_unique_user_count', 'event_type_entropy', 'is_failed_event',
            'time_since_last_user_event_seconds', 'global_event_rate',
            'hour_sin', 'hour_cos', 'day_sin', 'day_cos',
            'user_inter_event_mean', 'user_inter_event_std',
            'ip_entropy', 'user_entropy',
            'is_privileged_user', 'event_type_code',
            'threat_intel_malicious_ip', 'threat_intel_confidence', 'threat_intel_reputation_score',
            'recent_fail_sequence_length'
        ]
        
        return np.array([features.get(name, 0.0) for name in feature_names])
    
    def get_feature_names(self):
        """Return list of feature names in order"""
        return [
            'user_failed_event_count', 'user_total_event_count', 'user_success_rate',
            'ip_event_count', 'ip_failed_count', 'user_unique_ip_count', 
            'ip_unique_user_count', 'event_type_entropy', 'is_failed_event',
            'time_since_last_user_event_seconds', 'global_event_rate',
            'hour_sin', 'hour_cos', 'day_sin', 'day_cos',
            'user_inter_event_mean', 'user_inter_event_std',
            'ip_entropy', 'user_entropy',
            'is_privileged_user', 'event_type_code',
            'threat_intel_malicious_ip', 'threat_intel_confidence', 'threat_intel_reputation_score',
            'recent_fail_sequence_length'
        ]


if __name__ == "__main__":
    # Test Feature Extractor
    extractor = FeatureExtractor(window_size_minutes=60)
    
    test_logs = [
        {"timestamp": datetime.now().isoformat(), "user": "alice", "ip": "10.0.0.1", "event_type": "Login", "status": "SUCCESS"},
        {"timestamp": datetime.now().isoformat(), "user": "bob", "ip": "10.0.0.2", "event_type": "File_Access", "status": "SUCCESS"},
        {"timestamp": datetime.now().isoformat(), "user": "root", "ip": "192.168.1.100", "event_type": "Failed Login", "status": "FAILURE"},
        {"timestamp": datetime.now().isoformat(), "user": "root", "ip": "192.168.1.100", "event_type": "Failed Login", "status": "FAILURE"},
    ]
    
    for log in test_logs:
        features = extractor.extract_features(log)
        print(f"\nLog: {log['user']} - {log['event_type']}")
        print(f"Features: {features}")
        
        feature_vector = extractor.get_feature_vector(log)
        print(f"Feature Vector Shape: {feature_vector.shape}")
