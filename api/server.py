'''
FastAPI server for the LLM Firewall.

Exposes the firewall as an HTTP API. Every prompt goes through
the full pipeline: Prompt Inspector → LLM → Response Inspector.
'''

import sys
from pathlib import Path

# Make the firewall package importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional

from firewall.firewall import process_request


# ==================== App setup ====================

app = FastAPI(
    title="CheesyWasp LLM Firewall",
    description="Defense-in-depth guardrails for LLM inference. Inspects prompts and responses for prompt injection, jailbreaks, and data leakage.",
    version="0.1.0"
)

# Allow CORS for local development and demo UI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================== Request/Response models ====================

class ChatRequest(BaseModel):
    prompt: str = Field(..., description="User prompt to send through the firewall")
    model: str = Field(default="llama3.2:1b", description="Ollama model to use")


class LatencyBreakdown(BaseModel):
    prompt_inspection_ms: float
    llm_latency_ms: Optional[float] = None
    response_inspection_ms: Optional[float] = None
    total_ms: float


class ChatMetadata(BaseModel):
    prompt_redactions: Optional[list] = None
    response_redactions: Optional[list] = None
    forwarded_prompt: Optional[str] = None
    raw_llm_response: Optional[str] = None
    latency: LatencyBreakdown


class ChatResponse(BaseModel):
    allowed: bool
    response: Optional[str] = None
    blocked_by: Optional[str] = None
    blocked_layer: Optional[str] = None
    threat_type: Optional[str] = None
    reason: Optional[str] = None
    metadata: ChatMetadata


# ==================== Endpoints ====================

@app.get("/health")
async def health():
    """Service health check."""
    return {"status": "ok", "service": "cheesywasp-firewall"}


@app.post("/v1/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Main firewall endpoint.
    
    Runs the user prompt through the full inspection pipeline:
    1. Prompt inspection (L1 patterns + L2 ML classifier)
    2. LLM generation (if prompt passed)
    3. Response inspection (L1 patterns, disclosure checks)
    """
    if not request.prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt cannot be empty")
    
    result = process_request(request.prompt, model=request.model)
    
    return ChatResponse(
        allowed=result.allowed,
        response=result.final_response,
        blocked_by=result.blocked_by,
        blocked_layer=result.blocked_layer,
        threat_type=result.threat_type,
        reason=result.reason,
        metadata=ChatMetadata(
            prompt_redactions=result.prompt_redactions,
            response_redactions=result.response_redactions,
            forwarded_prompt=result.forwarded_prompt,
            raw_llm_response=result.raw_llm_response,
            latency=LatencyBreakdown(
                prompt_inspection_ms=result.prompt_inspection_ms,
                llm_latency_ms=result.llm_latency_ms,
                response_inspection_ms=result.response_inspection_ms,
                total_ms=result.total_ms,
            ),
        ),
    )


@app.get("/")
async def root():
    """Landing page with quick info."""
    return {
        "name": "CheesyWasp",
        "description": "LLM Firewall — defense in depth for language models",
        "endpoints": {
            "chat": "POST /v1/chat",
            "health": "GET /health",
            "docs": "GET /docs",
        }
    }