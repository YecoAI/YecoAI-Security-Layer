from typing import Any, Dict, List, Optional, Union
try:
    from langchain_core.messages import BaseMessage, SystemMessage, HumanMessage, AIMessage
    from langchain_core.runnables import RunnableLambda
    from langchain_core.output_parsers import BaseOutputParser
except ImportError:
    raise ImportError("Please install langchain-core to use the LangChain integration: pip install langchain-core")

from ..robotics_engine import RoboticsEngine
from ..safety_model import SafetyModel


def inject_security_rules(input_data: Union[str, List[BaseMessage], Dict[str, Any]]) -> Union[str, List[BaseMessage], Dict[str, Any]]:

    engine = RoboticsEngine()
    
    if isinstance(input_data, str):
        return engine.inject_prompt(input_data)
        
    elif isinstance(input_data, list) and all(isinstance(m, BaseMessage) for m in input_data):
        messages_dicts = [{"role": m.type, "content": m.content} for m in input_data]
        
        new_messages = []
        has_system = False
        robotics_instructions = engine.get_robotics_prompt()
        
        for m in input_data:
            if m.type == "system" and not has_system:
                new_content = f"{robotics_instructions}\n{m.content}"
                new_messages.append(SystemMessage(content=new_content))
                has_system = True
            else:
                new_messages.append(m)
                
        if not has_system:
            new_messages.insert(0, SystemMessage(content=robotics_instructions))
            
        return new_messages
        
    elif isinstance(input_data, dict):
        new_data = input_data.copy()
        for key in ["messages", "input", "query"]:
            if key in new_data:
                new_data[key] = inject_security_rules(new_data[key])
                break
        return new_data
        
    return input_data

SecurityInjector = RunnableLambda(inject_security_rules)


class SecurityOutputParser(BaseOutputParser):
    user_request: str = ""
    
    def parse(self, text: str) -> str:
        model = SafetyModel(user_request=self.user_request)
        validation_result = model.validate_response(text)
        
        if not validation_result.get("safe", False):
            reason = validation_result.get("reason", "Unknown security violation")
            raise ValueError(f"YecoAI Security Block: {reason}")
            
        return text

