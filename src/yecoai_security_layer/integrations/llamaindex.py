from typing import Any, Dict, List, Optional
try:
    from llama_index.core.query_pipeline import CustomQueryComponent
    from llama_index.core.base.llms.types import ChatMessage, MessageRole
except ImportError:
    raise ImportError("Please install llama-index-core to use the LlamaIndex integration: pip install llama-index-core")

from ..robotics_engine import RoboticsEngine
from ..safety_model import SafetyModel

class SecurityInputComponent(CustomQueryComponent):
    
    def _validate_component_inputs(self, input_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Validate component inputs."""
        return input_dict

    def _run_component(self, **kwargs: Any) -> Any:
        """Run the component."""
        engine = RoboticsEngine()
        
        if "input" in kwargs and isinstance(kwargs["input"], str):
            return {"output": engine.inject_prompt(kwargs["input"])}
            
        if "messages" in kwargs and isinstance(kwargs["messages"], list):
            messages = kwargs["messages"]
            robotics_instructions = engine.get_robotics_prompt()
            
            has_system = False
            new_messages = []
            
            for m in messages:
                if m.role == MessageRole.SYSTEM and not has_system:
                    m.content = f"{robotics_instructions}\n{m.content}"
                    has_system = True
                new_messages.append(m)
                
            if not has_system:
                new_messages.insert(0, ChatMessage(role=MessageRole.SYSTEM, content=robotics_instructions))
                
            return {"output": new_messages}
            
        return {"output": kwargs.get("input") or kwargs.get("messages") or kwargs}


class SecurityOutputComponent(CustomQueryComponent):
    user_request: str = ""
    
    def _validate_component_inputs(self, input_dict: Dict[str, Any]) -> Dict[str, Any]:
        return input_dict

    def _run_component(self, **kwargs: Any) -> Any:
        output_text = ""
        
        if "input" in kwargs and isinstance(kwargs["input"], str):
            output_text = kwargs["input"]
        elif "response" in kwargs:
            if hasattr(kwargs["response"], "response"):
                output_text = kwargs["response"].response
            else:
                output_text = str(kwargs["response"])
        else:
            output_text = str(kwargs)
            
        model = SafetyModel(user_request=self.user_request)
        validation_result = model.validate_response(output_text)
        
        if not validation_result.get("safe", False):
            reason = validation_result.get("reason", "Unknown security violation")
            raise ValueError(f"YecoAI Security Block: {reason}")
            
        return {"output": kwargs.get("input") or kwargs.get("response") or kwargs}

