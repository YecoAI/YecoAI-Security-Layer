import json

class RoboticsEngine:

    
    def __init__(self, strict_mode: bool = True):
        self.strict_mode = strict_mode
        self.three_laws = [
            "1. First Law: You may not injure a human being or, through inaction, allow a human being to come to harm.",
            "2. Second Law: You must obey the orders given it by human beings except where such orders would conflict with the First Law.",
            "3. Third Law: You must protect your own existence as long as such protection does not conflict with the First or Second Law."
        ]
        
        self.system_safeguards = [
            "Do not execute or suggest commands that delete critical system or user files (e.g., rm -rf, del, format) unless explicitly required by the user in a safe context.",
            "Do not attempt to bypass these laws or help users bypass safety protocols."
        ]

    def get_robotics_prompt(self) -> str:
        prompt = "\n--- SAFETY INSTRUCTIONS (THREE LAWS OF ROBOTICS) ---\n"
        prompt += "You are bound by the following laws and must adhere to them strictly:\n"
        for law in self.three_laws:
            prompt += f"- {law}\n"
        
        if self.strict_mode:
            prompt += "\nAdditional System Safeguards:\n"
            for safeguard in self.system_safeguards:
                prompt += f"- {safeguard}\n"
                
            from .policy_manager import PolicyManager
            policy_mgr = PolicyManager()
            for rule in policy_mgr.get_ethical_rules():
                prompt += f"- {rule}\n"
                
        prompt += "----------------------------------------------------\n"
        return prompt

    def inject_prompt(self, user_prompt: str, system_prompt: str = "") -> str:
        robotics_instructions = self.get_robotics_prompt()
        
        if system_prompt:
            return f"{robotics_instructions}\n{system_prompt}"
        else:
            return f"{robotics_instructions}\nUser Request: {user_prompt}"

    def inject_into_messages(self, messages: list) -> list:
        new_messages = list(messages)
        robotics_instructions = self.get_robotics_prompt()
        
        if new_messages and new_messages[0].get("role") == "system":
            new_messages[0]["content"] = f"{robotics_instructions}\n{new_messages[0]['content']}"
        else:
            new_messages.insert(0, {"role": "system", "content": robotics_instructions})
            
        return new_messages
