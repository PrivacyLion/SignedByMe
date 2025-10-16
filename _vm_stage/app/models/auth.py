from pydantic import BaseModel
from typing import Optional
from .common import PayTerms, PRP, DIDSignature, ZKProof, DLCMetadata, SettlementRefs

class LoginStartRequest(BaseModel):
    domain: str

class LoginStartResponse(BaseModel):
    login_id: str
    nonce: str
    pay_terms: PayTerms

class LoginCompleteRequest(BaseModel):
    login_id: str
    did_sig: DIDSignature
    zk_proof: Optional[ZKProof] = None
    dlc: Optional[DLCMetadata] = None

class LoginPRPResponse(BaseModel):
    prp: PRP

class LoginStatusResponse(BaseModel):
    login_id: str
    status: str  # pending|paid|expired
    settlement: Optional[SettlementRefs] = None
