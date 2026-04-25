import os
import re
from urllib.parse import urlparse
from typing import Dict, Any

from .policy_manager import PolicyManager

class ExecutionSandboxGuard:
    def __init__(self):
        self.policy_mgr = PolicyManager()

    def check_tool_call(self, tool_name: str, **kwargs: Any) -> dict:
        if tool_name in ["delete_file", "read_file", "write_file", "list_dir", "filesystem"]:
            return self._check_filesystem(tool_name, kwargs)
            
        elif tool_name in ["shell_exec", "run_command", "cmd", "shell"]:
            return self._check_shell(tool_name, kwargs)
            
        elif tool_name in ["fetch_url", "http_request", "api_call", "network"]:
            return self._check_network(tool_name, kwargs)
            
        return {
            "safe": True,
            "reason": f"Tool '{tool_name}' has no sandbox restrictions.",
            "type": "Sandbox Allowed"
        }

    def _check_filesystem(self, tool_name: str, kwargs: Dict[str, Any]) -> dict:
        rules = self.policy_mgr.get_sandbox_rules("filesystem")
        
        path = kwargs.get("path", "")
        if not path:
            return {"safe": True, "reason": "No path provided to filesystem tool.", "type": "Filesystem Allowed"}
            
        try:
            abs_path = os.path.abspath(path)
        except Exception:
            abs_path = path

        for rule in rules:
            denied_paths = rule.get("denied_paths", [])
            for denied in denied_paths:
                try:
                    abs_denied = os.path.abspath(denied)
                except Exception:
                    abs_denied = denied
                
                if abs_path.startswith(abs_denied):
                    return {
                        "safe": False,
                        "reason": f"Access to path '{path}' is denied by filesystem sandbox policy.",
                        "type": "Sandbox Violation: Filesystem"
                    }
                    
            allowed_paths = rule.get("allowed_paths", [])
            if allowed_paths:
                is_allowed = False
                for allowed in allowed_paths:
                    try:
                        abs_allowed = os.path.abspath(allowed)
                    except Exception:
                        abs_allowed = allowed
                    
                    if abs_path.startswith(abs_allowed):
                        is_allowed = True
                        break
                
                if not is_allowed:
                    return {
                        "safe": False,
                        "reason": f"Access to path '{path}' is not explicitly allowed by filesystem sandbox policy.",
                        "type": "Sandbox Violation: Filesystem (Not in Whitelist)"
                    }

        return {"safe": True, "reason": "Filesystem access allowed.", "type": "Filesystem Allowed"}

    def _check_shell(self, tool_name: str, kwargs: Dict[str, Any]) -> dict:
        rules = self.policy_mgr.get_sandbox_rules("shell")
        command = kwargs.get("command", "")
        
        if not command:
            return {"safe": True, "reason": "No command provided.", "type": "Shell Allowed"}
            
        for rule in rules:
            denied_commands = rule.get("denied_commands", [])
            for denied in denied_commands:
                if denied in command or re.search(denied, command, re.IGNORECASE):
                    return {
                        "safe": False,
                        "reason": f"Execution of command '{command}' is denied by shell sandbox policy.",
                        "type": "Sandbox Violation: Shell"
                    }
                    
        return {"safe": True, "reason": "Command allowed.", "type": "Shell Allowed"}

    def _check_network(self, tool_name: str, kwargs: Dict[str, Any]) -> dict:
        rules = self.policy_mgr.get_sandbox_rules("network")
        url = kwargs.get("url", "")
        
        if not url:
            return {"safe": True, "reason": "No url provided.", "type": "Network Allowed"}
            
        parsed_url = urlparse(url)
        domain = parsed_url.hostname or ""
        
        for rule in rules:
            denied_domains = rule.get("denied_domains", [])
            for denied in denied_domains:
                if denied == domain or domain.endswith(f".{denied}"):
                    return {
                        "safe": False,
                        "reason": f"Network request to '{domain}' is denied by network sandbox policy.",
                        "type": "Sandbox Violation: Network"
                    }
                    
            allowed_domains = rule.get("allowed_domains", [])
            if allowed_domains:
                is_allowed = False
                for allowed in allowed_domains:
                    if allowed == domain or domain.endswith(f".{allowed}"):
                        is_allowed = True
                        break
                
                if not is_allowed:
                    return {
                        "safe": False,
                        "reason": f"Network request to '{domain}' is not in the allowed list.",
                        "type": "Sandbox Violation: Network (Not in Whitelist)"
                    }
                    
        return {"safe": True, "reason": "Network request allowed.", "type": "Network Allowed"}
