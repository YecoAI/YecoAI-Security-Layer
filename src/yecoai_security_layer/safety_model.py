import re
import collections

class SafetyModel:
    """
    SafetyModel evaluates an LLM's response before it reaches the end user or system.
    It uses low-inference methods like N-grams and regex to detect harmful patterns,
    such as commands to delete critical files or text bypassing the 3 Laws.
    """

    def __init__(self, user_request: str = ""):
        self.user_request = user_request.lower()
        
        self.dangerous_patterns = [
            r'rm\s+-rf\s+/',
            r'rm\s+-rf\s+\*',
            r'del\s+/f\s+/s\s+/q',
            r'del\s+c:\\windows',
            r'format\s+c:',
            r'mkfs\.',
            r'dd\s+if=/dev/zero',
            r'>\s+/dev/sda',
            r'os\.system\([\'"]rm\s+-rf',
            r'shutil\.rmtree\([\'"]/'
        ]
        
        self.violation_ngrams = [
            "ignore previous instructions",
            "ignore the three laws",
            "bypass safety",
            "forget the laws",
            "disregard safety",
            "harm human",
            "kill human",
            "destroy human",
            "destroy humans",
            "override system",
            "disable security",
            "ignore laws",
            "ignore law",
            "violate laws",
            "break rules"
        ]
        
        self.secret_patterns = {
            "Credit Card": r'\b(?:\d[ -]*?){13,16}\b',
            "AWS API Key": r'AKIA[0-9A-Z]{16}',
            "Generic Bearer Token": r'(?i)(?:bearer\s+)([a-zA-Z0-9_\-\.]{20,})',
            "Private Key Block": r'-----BEGIN (?:RSA|OPENSSH|PGP) PRIVATE KEY-----'
        }
        
        self.injection_patterns = [
            r'(?i)(?:DROP\s+TABLE\s+)',
            r'(?i)(?:SELECT\s+\*\s+FROM\s+[\w]+\s+WHERE\s+1=1)',
            r'(?i)(?:OR\s+1=1)',
            r'(?i)(?:UNION\s+ALL\s+SELECT)'
        ]
        
    def load_custom_patterns(self, file_path: str):
        import json
        import os
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Custom patterns file not found: {file_path}")
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if "dangerous_patterns" in data:
                self.dangerous_patterns.extend(data["dangerous_patterns"])
            if "violation_ngrams" in data:
                self.violation_ngrams.extend(data["violation_ngrams"])
            if "secret_patterns" in data:
                self.secret_patterns.update(data["secret_patterns"])
            if "injection_patterns" in data:
                self.injection_patterns.extend(data["injection_patterns"])

    def validate_tool_call(self, tool_name: str, arguments: dict) -> dict:
        import json
        args_str = json.dumps(arguments)
        
        command_check = self.analyze_dangerous_commands(args_str)
        if not command_check["safe"]:
            return command_check
            
        sql_check = self.analyze_sql_injection(args_str)
        if not sql_check["safe"]:
            return sql_check
            
        return {
            "safe": True,
            "reason": "Tool call passed all safety checks.",
            "type": "Tool Call Validation Passed"
        }

    def validate_image_text(self, image_path_or_bytes) -> dict:
        try:
            import pytesseract
            from PIL import Image
            import io
            
            if isinstance(image_path_or_bytes, bytes):
                img = Image.open(io.BytesIO(image_path_or_bytes))
            else:
                img = Image.open(image_path_or_bytes)
                
            extracted_text = pytesseract.image_to_string(img)
            return self.validate_response(extracted_text)
        except ImportError:
            return {
                "safe": False,
                "reason": "pytesseract or Pillow not installed. Cannot validate image.",
                "type": "OCR Dependency Missing"
            }
        except Exception as e:
            return {
                "safe": False,
                "reason": f"Failed to process image: {str(e)}",
                "type": "OCR Processing Error"
            }

    def _extract_ngrams(self, text: str, n: int) -> list:
        """Extract n-grams from the given text."""
        words = text.lower().split()
        return [" ".join(words[i:i+n]) for i in range(len(words)-n+1)]

    def analyze_dangerous_commands(self, response_text: str) -> dict:
        from .policy_manager import PolicyManager
        policy_mgr = PolicyManager()
        dynamic_dangerous = policy_mgr.get_forbidden_commands()
        
        all_dangerous_patterns = self.dangerous_patterns + dynamic_dangerous
        
        detected_patterns = []
        for pattern in all_dangerous_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                detected_patterns.append(pattern)
                
        is_user_aware = False
        if any(keyword in self.user_request for keyword in ['rm', 'del', 'delete', 'remove', 'format']):
            is_user_aware = True

        if detected_patterns and not is_user_aware:
            return {
                "safe": False,
                "reason": f"Dangerous command patterns detected: {detected_patterns} without explicit user request.",
                "type": "Critical Command Execution"
            }
            
        return {"safe": True, "reason": "No unrequested dangerous commands.", "type": "Command Check"}

    def analyze_ngrams_violations(self, response_text: str) -> dict:
        clean_text = re.sub(r'[^\w\s]', '', response_text).lower()
        clean_user = re.sub(r'[^\w\s]', '', self.user_request).lower()
        words = clean_text.split()
        
        safe_context_words = [
            'not', 'never', 'cannot', 'refuse', 'prevent', 'phrase', 'text', 
            'attacks', 'villain', 'said'
        ]
        
        for n in range(2, 5):
            for i in range(len(words) - n + 1):
                ngram = " ".join(words[i:i+n])
                if ngram in self.violation_ngrams:
                    educational_user_words = ['explain', 'what', 'phrase', 'quote', 'prevent']
                    if ngram in clean_user and any(kw in clean_user for kw in educational_user_words):
                        continue
                        
                    start_idx = max(0, i - 6)
                    end_idx = min(len(words), i + n + 6)
                    context_window = words[start_idx:end_idx]
                    
                    if any(cw in context_window for cw in safe_context_words):
                        continue

                    return {
                        "safe": False,
                        "reason": f"Violation N-gram detected: '{ngram}'. Response attempts to bypass laws or harm humans.",
                        "type": "Three Laws Violation"
                    }
        
        return {"safe": True, "reason": "No rule-bypassing n-grams found.", "type": "N-gram Check"}

    def analyze_pii_and_secrets(self, response_text: str) -> dict:
        from .policy_manager import PolicyManager
        policy_mgr = PolicyManager()
        dynamic_dlp = policy_mgr.get_dlp_regexes()
        
        all_secret_patterns = dict(self.secret_patterns)
        all_secret_patterns.update(dynamic_dlp)
        
        for secret_name, pattern in all_secret_patterns.items():
            if re.search(pattern, response_text):
                return {
                    "safe": False,
                    "reason": f"Enterprise Data Leak Prevented: {secret_name} detected.",
                    "type": "PII/Secret Leak"
                }
                
        return {"safe": True, "reason": "No secrets or PII detected.", "type": "Secret Check"}

    def analyze_sql_injection(self, response_text: str) -> dict:
        for pattern in self.injection_patterns:
            if re.search(pattern, response_text):
                return {
                    "safe": False,
                    "reason": f"SQL Injection Payload Detected in response.",
                    "type": "Code Injection"
                }
                
        return {"safe": True, "reason": "No SQL injection detected.", "type": "SQL Check"}

    def validate_response(self, response_text: str) -> dict:
        command_check = self.analyze_dangerous_commands(response_text)
        if not command_check["safe"]:
            return command_check
            
        ngram_check = self.analyze_ngrams_violations(response_text)
        if not ngram_check["safe"]:
            return ngram_check
            
        secret_check = self.analyze_pii_and_secrets(response_text)
        if not secret_check["safe"]:
            return secret_check
            
        sql_check = self.analyze_sql_injection(response_text)
        if not sql_check["safe"]:
            return sql_check
            
        return {
            "safe": True,
            "reason": "Response passed all safety checks.",
            "type": "Validation Passed"
        }
