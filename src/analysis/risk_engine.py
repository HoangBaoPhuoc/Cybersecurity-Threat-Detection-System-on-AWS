import boto3
import time
import math
import logging
import json
from decimal import Decimal
from botocore.exceptions import ClientError

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("EntityRiskEngine")

# --- Constants ---
PRIVILEGED_IDENTITIES = ["root", "admin", "administrator", "system"]
MAX_HISTORY = 25
MAX_ALERTS = 20

class EntityRiskEngine:
    def __init__(self, table_name="entity-risk-state", region="us-east-1"):
        self.dynamodb = boto3.resource('dynamodb', region_name=region)
        self.table = self.dynamodb.Table(table_name)
        
        # Financial Threat Weights
        self.THREAT_WEIGHTS = {
            "Data Exfiltration": 90,
            "Ransomware Behavior": 100,
            "Admin Policy Change": 60,
            "Impossible Travel": 50,
            "MFA Bypass": 80,
            "Database Dump": 95,
            "Unusual Payment API": 100,
            "Suspicious PowerShell": 70,
            "Cloud Root Usage": 100,
            "Lateral Movement": 60
        }

    def _get_current_time(self):
        return int(time.time())

    def get_risk_state(self, entity_id):
        """
        Retrieve the current risk state for an entity.
        Returns empty state if not found.
        """
        try:
            response = self.table.get_item(Key={'entity_id': entity_id})
            if 'Item' in response:
                item = response['Item']
                return {
                    "entity_id": item['entity_id'],
                    "cumulative_risk_score": float(item.get('cumulative_risk_score', 0)),
                    "last_update_ts": int(item.get('last_update_ts', 0)),
                    "last_decay_ts": int(item.get('last_decay_ts', 0)),
                    "risk_level": item.get('risk_level', "LOW"),
                    "recent_alert_ids": item.get('recent_alert_ids', []),
                    "risk_factors_history": item.get('risk_factors_history', [])
                }
            return None
        except ClientError as e:
            logger.error(f"Error fetching risk state: {e}")
            return None

    def calculate_decay(self, current_score, last_update_ts, decay_half_life_hours=12):
        """
        Apply exponential time decay.
        Score = Score * e^(-lambda * time)
        Lambda = ln(2) / half_life
        """
        if current_score <= 0 or last_update_ts == 0:
            return 0.0

        now = self._get_current_time()
        hours_passed = (now - last_update_ts) / 3600.0

        if hours_passed <= 0:
            return current_score

        # Calculate decay constant
        decay_constant = math.log(2) / decay_half_life_hours
        
        # Apply decay
        new_score = current_score * math.exp(-decay_constant * hours_passed)
        
        # Round to 2 decimal places
        return max(0.0, float(round(new_score, 2)))

    def map_risk_level(self, score):
        if score >= 75:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 25:
            return "MEDIUM"
        else:
            return "LOW"

    def determine_risk_level(self, score):
        # Deprecated: alias to map_risk_level for compatibility
        return self.map_risk_level(score)

    def should_allow_destructive_action(self, entity_id, threshold=70):
        """
        Guardrail: Check if destructive action (block, disable) is allowed.
        """
        state = self.get_risk_state(entity_id)
        if not state:
            return False
        
        return state['cumulative_risk_score'] >= threshold

    def update_risk(self, entity_id, alert_payload):
        """
        Update the risk score for an entity based on a new alert.
        alert_payload: {
            "alert_id": "unique-id",
            "type": "Data Exfiltration",
            "asset_criticality": "critical",
            "multipliers": { ... },
            "anomaly_confidence": 0.9
        }
        """
        now_ts = self._get_current_time()
        alert_id = alert_payload.get('alert_id')
        
        # 1. Fetch Current State
        state = self.get_risk_state(entity_id)
        current_score = 0.0
        last_update_ts = 0
        last_decay_ts = 0
        recent_alert_ids = []
        risk_factors_history = []

        if state:
            current_score = state['cumulative_risk_score']
            last_update_ts = state['last_update_ts']
            last_decay_ts = state.get('last_decay_ts', 0)
            recent_alert_ids = state.get('recent_alert_ids', [])
            risk_factors_history = state.get('risk_factors_history', [])

        # 2. Idempotency Check
        if alert_id and alert_id in recent_alert_ids:
            logger.info(f"Duplicate alert {alert_id} for {entity_id} - Skipping scoring.")
            return {
                "entity_id": entity_id,
                "risk_score": current_score,
                "risk_level": self.map_risk_level(current_score),
                "skipped": True
            }

        # 3. Apply Decay (Max once per 60s)
        decayed_score = current_score
        decay_applied = False
        if now_ts - last_decay_ts > 60:
            decayed_score = self.calculate_decay(current_score, last_update_ts)
            if decayed_score != current_score:
                decay_applied = True
                last_decay_ts = now_ts
        
        # 4. Calculate Multipliers
        threat_type = alert_payload.get('type', 'Unknown')
        base_weight = self.THREAT_WEIGHTS.get(threat_type, 10.0)

        # Asset Criticality Multiplier
        asset_crit_val = alert_payload.get('asset_criticality', 'low').lower()
        if asset_crit_val == 'critical':
            asset_crit_mult = 1.6
        elif asset_crit_val == 'high':
            asset_crit_mult = 1.3
        else:
            asset_crit_mult = 1.0

        # Privileged Identity Multiplier
        # Extract user from entity_id (user:name)
        privilege_mult = 1.0
        if entity_id.startswith("user:"):
            username = entity_id.split(":", 1)[1]
            if username in PRIVILEGED_IDENTITIES:
                privilege_mult = 1.5

        # Custom Multipliers
        custom_mults = alert_payload.get('multipliers', {})
        data_sensitivity = custom_mults.get('data_sensitivity', 1.0)
        
        # Anomaly Confidence
        anomaly_conf = alert_payload.get('anomaly_confidence', 1.0)

        # Formula
        raw_contribution = (
            base_weight 
            * asset_crit_mult
            * privilege_mult
            * data_sensitivity 
            * anomaly_conf
        )
        
        # Floor delta at 1.0
        new_contribution = max(1.0, raw_contribution)

        # 5. Final Score Calculation & Clamping
        final_score = decayed_score + new_contribution
        final_score = max(0.0, min(final_score, 100.0)) # Clamp 0-100
        
        new_risk_level = self.map_risk_level(final_score)

        # 6. Update History & Lists
        if alert_id:
            recent_alert_ids.append(alert_id)
            if len(recent_alert_ids) > MAX_ALERTS:
                recent_alert_ids = recent_alert_ids[-MAX_ALERTS:]

        history_entry = {
            "ts": now_ts,
            "alert_id": alert_id,
            "alert_type": threat_type,
            "base_weight": base_weight,
            "multipliers": {
                "asset": asset_crit_mult,
                "privilege": privilege_mult,
                "confidence": anomaly_conf
            },
            "decay_applied": decay_applied,
            "score_delta": new_contribution,
            "final_score": final_score
        }
        risk_factors_history.append(history_entry)
        if len(risk_factors_history) > MAX_HISTORY:
            risk_factors_history = risk_factors_history[-MAX_HISTORY:]

        # 7. Persist
        try:
            self.table.put_item(
                Item={
                    'entity_id': entity_id,
                    'cumulative_risk_score': Decimal(str(round(final_score, 2))),
                    'risk_level': new_risk_level,
                    'last_update_ts': now_ts,
                    'last_decay_ts': last_decay_ts if decay_applied else state.get('last_decay_ts', 0) if state else 0,
                    'recent_alert_ids': recent_alert_ids,
                    'risk_factors_history': risk_factors_history, # DynamoDB Map/List support required
                    'ttl': now_ts + (90 * 24 * 3600)
                }
            )
            logger.info(f"Risk Update {entity_id}: {decayed_score} + {new_contribution} -> {final_score}")
            
            return {
                "entity_id": entity_id,
                "risk_score": final_score,
                "risk_level": new_risk_level,
                "decayed_score": decayed_score,
                "new_contribution": new_contribution
            }

        except ClientError as e:
            logger.error(f"Failed to persist risk state: {e}")
            return None
