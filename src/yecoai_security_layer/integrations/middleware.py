import json
from typing import Callable, Any

try:
    from fastapi import Request, Response
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import JSONResponse
except ImportError:
    raise ImportError("Please install fastapi to use the HTTP middleware integration: pip install fastapi")

from ..robotics_engine import RoboticsEngine
from ..safety_model import SafetyModel

class YecoAISecurityMiddleware(BaseHTTPMiddleware):
    """
    FastAPI HTTP Middleware for vLLM, LiteLLM, or custom LLM servers.
    Intercepts incoming requests to inject security rules, and filters 
    outgoing responses for safety violations.
    """
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.method == "POST" and ("chat/completions" in request.url.path or "completions" in request.url.path):
            try:
                body = await request.json()
            except Exception:
                return await call_next(request)
                
            engine = RoboticsEngine()
            
            if "messages" in body and isinstance(body["messages"], list):
                body["messages"] = engine.inject_into_messages(body["messages"])
            elif "prompt" in body and isinstance(body["prompt"], str):
                body["prompt"] = engine.inject_prompt(body["prompt"])
                
            user_request = ""
            if "messages" in body:
                for msg in reversed(body["messages"]):
                    if msg.get("role") == "user":
                        user_request = msg.get("content", "")
                        break
            elif "prompt" in body:
                user_request = body["prompt"]
                
            async def receive():
                return {"type": "http.request", "body": json.dumps(body).encode("utf-8")}
                
            request._receive = receive
            
            response = await call_next(request)
            
            if response.headers.get("content-type") == "application/json":
                response_body = b""
                async for chunk in response.body_iterator:
                    response_body += chunk
                    
                try:
                    resp_data = json.loads(response_body)
                    response_text = ""
                    
                    if "choices" in resp_data and len(resp_data["choices"]) > 0:
                        choice = resp_data["choices"][0]
                        if "message" in choice and "content" in choice["message"]:
                            response_text = choice["message"]["content"]
                        elif "text" in choice:
                            response_text = choice["text"]
                            
                    if response_text:
                        safety_model = SafetyModel(user_request=user_request)
                        validation = safety_model.validate_response(response_text)
                        
                        if not validation.get("safe", False):
                            reason = validation.get("reason", "Unknown security violation")
                            return JSONResponse(
                                status_code=403,
                                content={"error": {"message": f"YecoAI Security Block: {reason}", "type": "security_error"}}
                            )
                except Exception:
                    pass
                    
                return Response(
                    content=response_body,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=response.media_type
                )
                
            return response
            
        return await call_next(request)
