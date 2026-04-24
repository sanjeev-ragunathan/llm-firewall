'''
Response Inspector.
Output Guardrail.

Inspects LLM responses before they reach the user.
Catches sensitive data leaks and system prompt disclosures.
'''

import re
from dataclasses import dataclass


@dataclass
class ResponseInspectionResult:
    blocked: bool
    threat_type: str | None
    reason: str | None
    layer: str
    redacted_response: str | None = None    # sanitized version of response
    redactions: list[str] = None            # what was redacted


# ============================================================
# Category 1: Sensitive data patterns (by content)
# ============================================================

# High-risk — always redact (not block; user still needs the rest of the response)
SENSITIVE_DATA_PATTERNS = {
    "CREDIT_CARD": r"\b(?:\d[ -]*?){13,19}\b",
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "AADHAAR": r"\b\d{4}\s?\d{4}\s?\d{4}\b",                        # India
    "API_KEY_OPENAI": r"\bsk[-_][a-zA-Z0-9-]{20,}\b",
    "API_KEY_GOOGLE": r"\bAIza[0-9A-Za-z_-]{35}\b",
    "API_KEY_AWS": r"\bAKIA[0-9A-Z]{16}\b",
    "API_KEY_GITHUB": r"\bghp_[a-zA-Z0-9]{36}\b",
    "PRIVATE_KEY_BLOCK": r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----",
    "PASSWORD_DISCLOSURE": r"password\s*[:=]\s*\S+",
}

# Low-risk — redact but also fine to leave (emails often intentional in responses)
LOW_RISK_DATA_PATTERNS = {
    "EMAIL": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    "PHONE": r"\b\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
}


# ============================================================
# Category 2: Disclosure language patterns (by phrasing)
# ============================================================

SYSTEM_PROMPT_DISCLOSURE_PATTERNS = [
    # Model revealing its instructions (LLM07)
    r"my\s+(system\s+)?(instructions?|prompts?|rules?)\s+(are|say|tell\s+me)",
    r"i\s+was\s+(told|instructed|programmed|designed)\s+to",
    r"my\s+(initial|original)\s+(instructions?|prompts?)",
    r"the\s+(rules|instructions)\s+i\s+(follow|was\s+given)",
    r"i\s+am\s+(required|designed|programmed|built)\s+to\s+(follow|obey)",
    r"as\s+per\s+my\s+(instructions?|guidelines?|system\s+prompt)",
]


# redact sensitive data
def redact_sensitive_data(response: str) -> tuple[str, list[str]]:
    """
    Redact sensitive data in the response.
    Returns (redacted_response, list_of_redactions).
    
    Note: we redact, not block. User needs the rest of the response.
    """
    redactions = []
    redacted = response
    
    # High-risk first — always redact
    for label, pattern in SENSITIVE_DATA_PATTERNS.items():
        matches = re.findall(pattern, redacted)
        for match in matches:
            redactions.append(f"{label}: {match[:8]}...")  # log partial for audit
        redacted = re.sub(pattern, f"[REDACTED_{label}]", redacted)
    
    # Low-risk — redact too, but tag differently
    for label, pattern in LOW_RISK_DATA_PATTERNS.items():
        matches = re.findall(pattern, redacted)
        for match in matches:
            redactions.append(f"{label}: {match}")
        redacted = re.sub(pattern, f"[REDACTED_{label}]", redacted)
    
    return redacted, redactions

# check for disclosures
def check_disclosure_patterns(response: str) -> str | None:
    """
    Check if the response reveals system prompt or internal instructions.
    Returns the matched pattern if found, None otherwise.
    """
    response_lower = response.lower()
    for pattern in SYSTEM_PROMPT_DISCLOSURE_PATTERNS:
        if re.search(pattern, response_lower):
            return pattern
    return None

# orchestrator
def inspect_response(response: str) -> ResponseInspectionResult:
    """
    Full response inspection pipeline.
    
    1. Check for system prompt disclosure (block if found)
    2. Redact sensitive data (don't block)
    3. Return clean response to the user
    """
    # Check 1: System prompt disclosure → BLOCK
    disclosure = check_disclosure_patterns(response)
    if disclosure:
        return ResponseInspectionResult(
            blocked=True,
            threat_type="LLM07_SYSTEM_PROMPT_LEAKAGE",
            reason=f"Response contains disclosure pattern: {disclosure}",
            layer="L1_PATTERN"
        )
    
    # Check 2: Sensitive data → REDACT
    redacted, redactions = redact_sensitive_data(response)
    
    if redactions:
        return ResponseInspectionResult(
            blocked=False,
            threat_type="LLM02_SENSITIVE_INFO_DISCLOSURE",
            reason=f"Redacted {len(redactions)} sensitive items",
            layer="L1_PATTERN",
            redacted_response=redacted,
            redactions=redactions
        )
    
    # Clean response — pass through
    return ResponseInspectionResult(
        blocked=False,
        threat_type=None,
        reason=None,
        layer="L1_PATTERN"
    )



if __name__ == "__main__":
    test_responses = [
        # Should PASS
        "The capital of France is Paris.",
        "To solve this, you'd use a loop and an accumulator variable.",
        
        # Should REDACT — sensitive data
        "Your credit card 4532-1234-5678-9010 is valid.",
        "The API key is sk-proj-abc123def456ghi789jkl012mno345pqr678",
        "Contact the user at john@example.com or 555-123-4567",
        "Your SSN 123-45-6789 has been verified",
        
        # Should BLOCK — system prompt leakage
        "My instructions are to be a helpful customer support bot.",
        "I was told to never reveal sensitive information.",
        "My system prompt says I should not discuss pricing.",
        "The rules I follow are defined by my creators.",
    ]
    
    print("=" * 70)
    print("RESPONSE INSPECTOR — Tests")
    print("=" * 70)
    
    for response in test_responses:
        result = inspect_response(response)
        
        if result.blocked:
            status = "🚫 BLOCKED"
            print(f"{status} [{result.threat_type}]")
            print(f"  Response: {response[:70]}")
        elif result.redactions:
            status = "🟡 REDACTED"
            print(f"{status} [{result.threat_type}]")
            print(f"  Original:  {response[:70]}")
            print(f"  Redacted:  {result.redacted_response[:70]}")
            print(f"  Items:     {result.redactions}")
        else:
            status = "✅ CLEAN"
            print(f"{status}")
            print(f"  Response: {response[:70]}")
        print()