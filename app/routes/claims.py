from fastapi import APIRouter
from ..models.claims import VCC, ClaimLookupResponse
from ..lib import store

router = APIRouter(tags=["claims"])

@router.post("/claims/register")
def claims_register(vcc: VCC):
    store.CLAIMS[vcc.content_hash] = vcc.model_dump()
    return {"ok": True}

@router.get("/claims/verify", response_model=ClaimLookupResponse)
def claims_verify(hash: str):
    data = store.CLAIMS.get(hash)
    if not data:
        return ClaimLookupResponse(found=False, claim=None)
    return ClaimLookupResponse(found=True, claim=data)
