import functools
from typing import Any, Callable, Dict, List, Optional

from ..robotics_engine import RoboticsEngine
from ..safety_model import SafetyModel


def secure_chat_completion(
    client_call: Callable, 
    messages: List[Dict[str, str]], 
    **kwargs: Any
) -> Any:
    """
    A pure wrapper for OpenAI, Anthropic, or similar API calls.
    
    Usage:
        from openai import OpenAI
        client = OpenAI()
        
        response = secure_chat_completion(
            client.chat.completions.create,
            messages=[{"role": "user", "content": "Hello"}],
            model="gpt-4o"
        )
        
    It intercepts the input messages to inject Robotics rules, 
    and filters the output text to ensure it complies with SafetyModel.
    """
    engine = RoboticsEngine()
    
    secure_messages = engine.inject_into_messages(messages)
    
    user_request = ""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            user_request = msg.get("content", "")
            break
            
    response = client_call(messages=secure_messages, **kwargs)
    
    response_text = ""
    try:
        if hasattr(response, "choices") and response.choices:
            response_text = response.choices[0].message.content
        elif hasattr(response, "content") and isinstance(response.content, list):
            response_text = response.content[0].text
        elif isinstance(response, dict):
            if "choices" in response:
                response_text = response["choices"][0]["message"]["content"]
            elif "content" in response:
                response_text = response["content"][0]["text"]
    except Exception:
        response_text = str(response)
        
    safety_model = SafetyModel(user_request=user_request)
    validation = safety_model.validate_response(response_text)
    
    if not validation.get("safe", False):
        reason = validation.get("reason", "Unknown security violation")
        raise ValueError(f"YecoAI Security Block: {reason}")
        
    return response

def secure_anthropic_messages(
    client_call: Callable,
    messages: List[Dict[str, str]],
    system: str = "",
    **kwargs: Any
) -> Any:
    engine = RoboticsEngine()
    
    secure_system = engine.inject_prompt("", system_prompt=system)
    
    user_request = ""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            user_request = msg.get("content", "")
            break
            
    response = client_call(messages=messages, system=secure_system, **kwargs)
    
    response_text = ""
    try:
        if hasattr(response, "content") and isinstance(response.content, list):
            response_text = response.content[0].text
        else:
            response_text = str(response)
    except Exception:
        response_text = str(response)
        
    safety_model = SafetyModel(user_request=user_request)
    validation = safety_model.validate_response(response_text)
    
    if not validation.get("safe", False):
        reason = validation.get("reason", "Unknown security violation")
        raise ValueError(f"YecoAI Security Block: {reason}")
        
    return response
