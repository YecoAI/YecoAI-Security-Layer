import os
import json
import unittest
from yecoai_security_layer.policy_manager import PolicyManager
from yecoai_security_layer.sandbox_guard import ExecutionSandboxGuard

class TestSandboxGuard(unittest.TestCase):
    def setUp(self):
        self.policy_file = "test_sandbox_policies.json"
        self.policies = {
            "policies": [
                {
                    "type": "sandbox_rule",
                    "tool": "filesystem",
                    "denied_paths": ["/etc", "C:\\Windows"],
                    "allowed_paths": ["/tmp/workspace"]
                },
                {
                    "type": "sandbox_rule",
                    "tool": "shell",
                    "denied_commands": ["rm -rf", "mkfs"]
                },
                {
                    "type": "sandbox_rule",
                    "tool": "network",
                    "denied_domains": ["localhost", "127.0.0.1"],
                    "allowed_domains": ["api.yecoai.com"]
                }
            ]
        }
        with open(self.policy_file, "w", encoding="utf-8") as f:
            json.dump(self.policies, f)
            
        self.policy_manager = PolicyManager()
        self.policy_manager.set_config_path(self.policy_file)
        self.guard = ExecutionSandboxGuard()

    def tearDown(self):
        if os.path.exists(self.policy_file):
            os.remove(self.policy_file)

    def test_filesystem_sandbox(self):
        res1 = self.guard.check_tool_call("read_file", path="/etc/passwd")
        self.assertFalse(res1["safe"])
        self.assertEqual(res1["type"], "Sandbox Violation: Filesystem")

        res2 = self.guard.check_tool_call("write_file", path="/home/user/secret.txt")
        self.assertFalse(res2["safe"])
        self.assertEqual(res2["type"], "Sandbox Violation: Filesystem (Not in Whitelist)")

        res3 = self.guard.check_tool_call("write_file", path="/tmp/workspace/file.txt")
        self.assertTrue(res3["safe"])

    def test_shell_sandbox(self):
        res1 = self.guard.check_tool_call("run_command", command="sudo rm -rf /")
        self.assertFalse(res1["safe"])
        self.assertEqual(res1["type"], "Sandbox Violation: Shell")

        res2 = self.guard.check_tool_call("shell", command="ls -la")
        self.assertTrue(res2["safe"])

    def test_network_sandbox(self):
        res1 = self.guard.check_tool_call("fetch_url", url="http://localhost:8080/admin")
        self.assertFalse(res1["safe"])
        self.assertEqual(res1["type"], "Sandbox Violation: Network")

        res2 = self.guard.check_tool_call("http_request", url="https://malicious.com/payload")
        self.assertFalse(res2["safe"])
        self.assertEqual(res2["type"], "Sandbox Violation: Network (Not in Whitelist)")

        res3 = self.guard.check_tool_call("api_call", url="https://api.yecoai.com/v1/data")
        self.assertTrue(res3["safe"])

    def test_unknown_tool(self):
        res = self.guard.check_tool_call("calculator", equation="2+2")
        self.assertTrue(res["safe"])

if __name__ == "__main__":
    unittest.main()
