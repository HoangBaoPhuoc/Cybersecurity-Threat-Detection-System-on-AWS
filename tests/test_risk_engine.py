import unittest
import sys
import os
from unittest.mock import MagicMock

# Mock boto3 before importing risk_engine
sys.modules["boto3"] = MagicMock()
sys.modules["botocore"] = MagicMock()
sys.modules["botocore.exceptions"] = MagicMock()

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src/analysis')))

from risk_engine import EntityRiskEngine

class MockTable:
    def __init__(self):
        self.items = {}

    def get_item(self, Key):
        entity_id = Key['entity_id']
        if entity_id in self.items:
            return {'Item': self.items[entity_id]}
        return {}

    def put_item(self, Item):
        self.items[Item['entity_id']] = Item

class TestEntityRiskEngine(unittest.TestCase):
    def setUp(self):
        os.environ["DECAY_FACTOR"] = "0.98"
        os.environ["DECAY_TIME_UNIT_SECONDS"] = "3600"
        self._now = 1000000

        self.engine = EntityRiskEngine(time_provider=lambda: self._now)
        # Mock DynamoDB Table
        self.engine.table = MockTable()

    def test_initial_risk(self):
        res = self.engine.update_risk("user:test1", {
            "severity": "HIGH"
        })
        self.assertEqual(res["risk_score"], 60.0)
        self.assertEqual(res["decayed_score"], 0.0)

    def test_multiplier_context(self):
        res = self.engine.update_risk("ip:1.2.3.4", {
            "severity": "HIGH",
            "context": {"untrusted_ip": True, "admin_role": True}
        })
        # 60 * (1.5 * 1.4) = 126
        self.assertEqual(res["multiplier"], 2.1)
        self.assertEqual(res["risk_score"], 126.0)

    def test_decay_formula(self):
        first = self.engine.update_risk("user:decay", {"severity": "HIGH"})
        self.assertEqual(first["risk_score"], 60.0)

        self._now += 3600
        second = self.engine.update_risk("user:decay", {"severity": "LOW"})
        expected = 60.0 * 0.98 + 10.0
        self.assertAlmostEqual(second["risk_score"], expected, places=4)

    def test_explicit_multiplier(self):
        res = self.engine.update_risk("user:explicit", {
            "severity": "MEDIUM",
            "multiplier": 2.5
        })
        self.assertEqual(res["risk_score"], 75.0)

if __name__ == '__main__':
    unittest.main()
