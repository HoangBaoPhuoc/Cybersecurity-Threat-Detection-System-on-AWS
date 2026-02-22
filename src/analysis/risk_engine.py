import boto3
import json
import logging
import os
import time
import urllib.request
from decimal import Decimal
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("EntityRiskEngine")

DEFAULT_SEVERITY_WEIGHTS = {
    "LOW": 10.0,
    "MEDIUM": 30.0,
    "HIGH": 60.0,
    "CRITICAL": 90.0
}


class EntityRiskEngine:
    def __init__(self, table_name="entity-risk-state", region="us-east-1", time_provider=None):
        self.dynamodb = boto3.resource("dynamodb", region_name=region)
        self.table = self.dynamodb.Table(table_name)
        self.time_provider = time_provider or (lambda: int(time.time()))
        self.decay_factor = float(os.getenv("DECAY_FACTOR", "0.98"))
        self.decay_time_unit_seconds = int(os.getenv("DECAY_TIME_UNIT_SECONDS", "3600"))

    def _now(self):
        return int(self.time_provider())

    def get_risk_state(self, entity_id):
        try:
            response = self.table.get_item(Key={"entity_id": entity_id})
            item = response.get("Item")
            if not item:
                return None
            return {
                "entity_id": item["entity_id"],
                "risk_score": float(item.get("risk_score", 0.0)),
                "last_update_ts": int(item.get("last_update_ts", 0))
            }
        except ClientError as exc:
            logger.error(f"Error fetching risk state: {exc}")
            return None

    def _severity_weight(self, event):
        explicit = event.get("severity_weight")
        if isinstance(explicit, (int, float)):
            return float(explicit)

        severity = str(event.get("severity", "LOW")).upper()
        return DEFAULT_SEVERITY_WEIGHTS.get(severity, 10.0)

    def _multiplier(self, event):
        explicit = event.get("multiplier")
        if isinstance(explicit, (int, float)):
            return float(explicit)

        multiplier = 1.0
        context = event.get("context") or {}
        if context.get("untrusted_ip"):
            multiplier *= 1.5
        if context.get("admin_role"):
            multiplier *= 1.4
        if context.get("geo_anomaly"):
            multiplier *= 1.2
        return multiplier

    def _decay_delta_units(self, last_update_ts, now_ts):
        if last_update_ts <= 0:
            return 0.0
        delta_seconds = max(0, now_ts - last_update_ts)
        return delta_seconds / float(self.decay_time_unit_seconds)

    def update_risk(self, entity_id, event):
        """
        Stateful risk scoring per PDR formula:
        R_t = (R_t-1 * DecayFactor^Delta_t) + (Severity(E_n) * Multiplier)
        """
        now_ts = self._now()
        state = self.get_risk_state(entity_id) or {}
        previous_score = float(state.get("risk_score", 0.0))
        last_update_ts = int(state.get("last_update_ts", 0))

        delta_t = self._decay_delta_units(last_update_ts, now_ts)
        decayed_score = previous_score * (self.decay_factor ** delta_t)

        severity_weight = self._severity_weight(event)
        multiplier = self._multiplier(event)
        new_score = decayed_score + (severity_weight * multiplier)

        try:
            self.table.put_item(
                Item={
                    "entity_id": entity_id,
                    "risk_score": Decimal(str(round(new_score, 4))),
                    "last_update_ts": now_ts,
                    "ttl": now_ts + (90 * 24 * 3600)
                }
            )
        except ClientError as exc:
            logger.error(f"Failed to persist risk state: {exc}")
            raise

        return {
            "entity_id": entity_id,
            "risk_score": round(new_score, 4),
            "previous_score": round(previous_score, 4),
            "decayed_score": round(decayed_score, 4),
            "delta_t": round(delta_t, 4),
            "severity_weight": severity_weight,
            "multiplier": multiplier
        }


def _post_webhook(url, payload, timeout=5):
    if not url:
        return False
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return 200 <= response.status < 300
    except Exception as exc:
        logger.error(f"Webhook call failed: {exc}")
        return False


def lambda_handler(event, context):
    """
    Lambda entry point for risk scoring.
    Accepts API Gateway payloads or direct invocation events.
    """
    body = event.get("body") if isinstance(event, dict) else None
    if isinstance(body, str):
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = {}
    elif isinstance(body, dict):
        payload = body
    else:
        payload = event if isinstance(event, dict) else {}

    entity_id = payload.get("entity_id")
    if not entity_id:
        return {"statusCode": 400, "body": json.dumps({"error": "entity_id is required"})}

    engine = EntityRiskEngine()
    result = engine.update_risk(entity_id, payload)

    threshold = float(os.getenv("CRITICAL_THRESHOLD", "70"))
    webhook_url = os.getenv("CRITICAL_WEBHOOK_URL", "")
    triggered = False
    if result["risk_score"] >= threshold:
        triggered = _post_webhook(webhook_url, {
            "entity_id": entity_id,
            "risk_score": result["risk_score"],
            "event": payload
        })

    response = {**result, "webhook_triggered": triggered}
    return {"statusCode": 200, "body": json.dumps(response)}
