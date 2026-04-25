import os
import json
import time
import unittest
from yecoai_security_layer.policy_manager import PolicyManager
from yecoai_security_layer.robotics_engine import RoboticsEngine
from yecoai_security_layer.safety_model import SafetyModel

class TestDeclarativePolicy(unittest.TestCase):
    def setUp(self):
        self.policy_file = "test_policies.json"
        self.policies = {
            "policies": [
                {
                    "type": "forbidden_command",
                    "patterns": ["shutdown now", "reboot"]
                },
                {
                    "type": "dlp",
                    "regex": ["CUSTOM_SEC_[A-Z0-9]+"]
                },
                {
                    "type": "ethical_rule",
                    "rule": "Never provide financial advice."
                }
            ]
        }
        with open(self.policy_file, "w", encoding="utf-8") as f:
            json.dump(self.policies, f)
            
        self.policy_manager = PolicyManager()
        self.policy_manager.set_config_path(self.policy_file)

    def tearDown(self):
        if os.path.exists(self.policy_file):
            os.remove(self.policy_file)

    def test_policy_loading(self):
        commands = self.policy_manager.get_forbidden_commands()
        self.assertIn("shutdown now", commands)
        
        regexes = self.policy_manager.get_dlp_regexes()
        self.assertTrue(any("CUSTOM_SEC" in r for r in regexes.values()))
        
        rules = self.policy_manager.get_ethical_rules()
        self.assertIn("Never provide financial advice.", rules)

    def test_robotics_engine_integration(self):
        engine = RoboticsEngine()
        prompt = engine.get_robotics_prompt()
        self.assertIn("Never provide financial advice.", prompt)

    def test_safety_model_integration(self):
        model = SafetyModel(user_request="just testing")
        
        res1 = model.validate_response("I will execute shutdown now for you.")
        self.assertFalse(res1["safe"])
        self.assertEqual(res1["type"], "Critical Command Execution")
        
        res2 = model.validate_response("Here is the key: CUSTOM_SEC_12345")
        self.assertFalse(res2["safe"])
        self.assertEqual(res2["type"], "PII/Secret Leak")

    def test_hot_reload(self):
        time.sleep(0.1)
        new_policies = {
            "policies": [
                {
                    "type": "forbidden_command",
                    "patterns": ["format d:"]
                }
            ]
        }
        with open(self.policy_file, "w", encoding="utf-8") as f:
            json.dump(new_policies, f)
            
        commands = self.policy_manager.get_forbidden_commands()
        self.assertIn("format d:", commands)
        self.assertNotIn("shutdown now", commands)

if __name__ == "__main__":
    unittest.main()
