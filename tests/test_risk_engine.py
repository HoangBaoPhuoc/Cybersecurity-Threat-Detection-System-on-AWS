import unittest
import time
import sys
import os
from unittest.mock import MagicMock
from decimal import Decimal

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
        self.engine = EntityRiskEngine()
        # Mock DynamoDB Table
        self.engine.table = MockTable()

    def test_initial_risk(self):
        """Test risk calculation for a new entity"""
        res = self.engine.update_risk("user:test1", {
            "type": "Data Exfiltration",
            "asset_criticality": "low"
        })
        # Base weight 90 * 1.0 = 90
        self.assertEqual(res['risk_score'], 90.0)
        self.assertEqual(res['risk_level'], "CRITICAL")

    def test_clamping(self):
        """Test score clamping at 100"""
        res = self.engine.update_risk("user:superrisk", {
            "type": "Data Exfiltration", # 90
            "multipliers": {"data_sensitivity": 10.0} # 900
        })
        self.assertEqual(res['risk_score'], 100.0)

    def test_idempotency(self):
        """Test alert duplication check"""
        # First Call
        res1 = self.engine.update_risk("user:idem", {
            "alert_id": "alert-123",
            "type": "Impossible Travel" # 50
        })
        self.assertEqual(res1['risk_score'], 50.0)

        # Second Call (Same ID)
        res2 = self.engine.update_risk("user:idem", {
            "alert_id": "alert-123",
            "type": "Impossible Travel"
        })
        self.assertEqual(res2['risk_score'], 50.0)
        self.assertTrue(res2.get('skipped', False))

        # Check DynamoDB state
        item = self.engine.table.items["user:idem"]
        self.assertIn("alert-123", item['recent_alert_ids'])

    def test_privileged_multiplier(self):
        """Test privileged user multiplier"""
        # root user
        res = self.engine.update_risk("user:root", {
            "type": "Suspicious PowerShell" # 70
        })
        # 70 * 1.5 (Privilege) = 105 -> Clamp 100
        self.assertEqual(res['risk_score'], 100.0)

        # normal user
        res2 = self.engine.update_risk("user:regular", {
            "type": "Suspicious PowerShell" # 70
        })
        self.assertEqual(res2['risk_score'], 70.0)

    def test_asset_criticality(self):
        """Test asset criticality multiplier"""
        res = self.engine.update_risk("ip:1.1.1.1", {
            "type": "Lateral Movement", # 60
            "asset_criticality": "critical" # 1.6
        })
        # 60 * 1.6 = 96.0
        self.assertEqual(res['risk_score'], 96.0)

    def test_guardrail(self):
        """Test should_allow_destructive_action"""
        self.engine.update_risk("user:lowrisk", {
            "type": "Impossible Travel" # 50 (Medium)
        })
        
        # Threshold 70
        self.assertFalse(self.engine.should_allow_destructive_action("user:lowrisk"))
        
        # Bump up
        self.engine.update_risk("user:lowrisk", {
            "type": "Impossible Travel" # +50 = 100
        })
        self.assertTrue(self.engine.should_allow_destructive_action("user:lowrisk"))

    def test_history_cap(self):
        """Test history trimming"""
        for i in range(30):
            self.engine.update_risk("user:hist", {
                "alert_id": f"alert-{i}",
                "type": "Admin Policy Change"
            })
            
        item = self.engine.table.items["user:hist"]
        self.assertEqual(len(item['risk_factors_history']), 25)
        self.assertEqual(len(item['recent_alert_ids']), 20)

if __name__ == '__main__':
    unittest.main()
