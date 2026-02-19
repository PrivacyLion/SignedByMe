from pydantic import BaseModel
from typing import Optional, Dict, Any

class VCC(BaseModel):
    created_by: str
    content_hash: str
    ln_address: str
    origin_claim: Optional[str] = None
    split: Optional[str] = None
    extra: Optional[Dict[str, Any]] = None
    signature_hex: str

class ClaimLookupResponse(BaseModel):
    found: bool
    claim: Optional[VCC] = None
