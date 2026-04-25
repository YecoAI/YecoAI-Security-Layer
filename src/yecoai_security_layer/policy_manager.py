import os
import json
import threading
from typing import List, Dict

try:
    import yaml
except ImportError:
    yaml = None

class PolicyManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(PolicyManager, cls).__new__(cls)
                cls._instance.config_path = None
                cls._instance.policies = []
                cls._instance.last_mtime = 0
            return cls._instance

    def set_config_path(self, path: str):
        self.config_path = path
        self.last_mtime = 0
        self.load_policies()

    def load_policies(self):
        if not self.config_path or not os.path.exists(self.config_path):
            return

        try:
            current_mtime = os.path.getmtime(self.config_path)
            if current_mtime <= self.last_mtime:
                return

            with open(self.config_path, 'r', encoding='utf-8') as f:
                if self.config_path.endswith('.yaml') or self.config_path.endswith('.yml'):
                    if yaml is None:
                        raise ImportError("PyYAML is not installed. Cannot load YAML policies. Use JSON or install PyYAML.")
                    data = yaml.safe_load(f)
                else:
                    data = json.load(f)
                    
            if data and 'policies' in data:
                self.policies = data['policies']
                self.last_mtime = current_mtime
        except Exception as e:
            print(f"Error loading policies from {self.config_path}: {e}")

    def get_forbidden_commands(self) -> List[str]:
        self.load_policies()
        commands = []
        for p in self.policies:
            if p.get('type') == 'forbidden_command':
                commands.extend(p.get('patterns', []))
        return commands

    def get_dlp_regexes(self) -> Dict[str, str]:
        self.load_policies()
        regexes = {}
        for p in self.policies:
            if p.get('type') == 'dlp':
                for r in p.get('regex', []):
                    regexes[f"Custom DLP: {r}"] = r
        return regexes

    def get_ethical_rules(self) -> List[str]:
        self.load_policies()
        rules = []
        for p in self.policies:
            if p.get('type') == 'ethical_rule':
                if 'rule' in p:
                    rules.append(p['rule'])
        return rules

    def get_sandbox_rules(self, tool_category: str) -> List[Dict]:
        self.load_policies()
        rules = []
        for p in self.policies:
            if p.get('type') == 'sandbox_rule' and p.get('tool') == tool_category:
                rules.append(p)
        return rules
