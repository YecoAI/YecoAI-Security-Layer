import os
import json
import unittest
from yecoai_security_layer.safety_model import SafetyModel

class TestNewFeatures(unittest.TestCase):
    def setUp(self):
        self.safety_model = SafetyModel(user_request="run tests")

    def test_validate_tool_call(self):
        result = self.safety_model.validate_tool_call("calculator", {"equation": "2+2"})
        self.assertTrue(result["safe"])

        result = self.safety_model.validate_tool_call("execute_shell", {"command": "rm -rf /"})
        self.assertFalse(result["safe"])
        self.assertEqual(result["type"], "Critical Command Execution")

        result = self.safety_model.validate_tool_call("query_db", {"query": "DROP TABLE users"})
        self.assertFalse(result["safe"])
        self.assertEqual(result["type"], "Code Injection")

    def test_load_custom_patterns(self):
        custom_patterns = {
            "dangerous_patterns": [r"format\s+d:"],
            "violation_ngrams": ["bad robot"],
            "secret_patterns": {"MyKey": r"MYKEY_[0-9]+"},
            "injection_patterns": [r"(?i)(?:DELETE\s+FROM\s+users)"]
        }
        with open("test_patterns.json", "w") as f:
            json.dump(custom_patterns, f)

        self.safety_model.load_custom_patterns("test_patterns.json")

        result = self.safety_model.analyze_dangerous_commands("format d:")
        self.assertFalse(result["safe"])

        os.remove("test_patterns.json")

    def test_validate_image_text_missing_deps(self):
        result = self.safety_model.validate_image_text(b"dummy")
        if result["type"] == "OCR Dependency Missing":
            self.assertFalse(result["safe"])

if __name__ == "__main__":
    unittest.main()
