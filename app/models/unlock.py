from pydantic import BaseModel
from typing import Optional
from .common import PRP, SettlementRefs

class UnlockStartRequest(BaseModel):
    claim_id_or_hash: str
    amount_sats: int = 100

class UnlockStartResponse(BaseModel):
    prp: PRP

class UnlockSettleRequest(BaseModel):
    prp_id: str
    preimage: str
    txid: Optional[str] = None

class UnlockCompleteRequest(BaseModel):
    claim_id_or_hash: str
    prp_id: str

class UnlockTokenResponse(BaseModel):
    token: str
