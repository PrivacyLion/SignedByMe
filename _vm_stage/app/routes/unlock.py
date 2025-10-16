import time, uuid, os
from fastapi import APIRouter, HTTPException
from ..models.unlock import (
    UnlockStartRequest, UnlockStartResponse, UnlockSettleRequest,
    UnlockCompleteRequest, UnlockTokenResponse
)
from ..models.common import PRP, SettlementRefs
from ..lib.crypto import hmac_token
from ..lib import store

router = APIRouter(tags=["unlock"])
PRP_TTL = int(os.getenv("PRP_EXPIRES_SECS", "180"))

@router.post("/unlock/start", response_model=UnlockStartResponse)
def unlock_start(body: UnlockStartRequest):
    prp_id = uuid.uuid4().hex[:16]
    prp = PRP(
        prp_id=prp_id,
        kind="unlock",
        payload={"claim_id_or_hash": body.claim_id_or_hash, "amount_sats": body.amount_sats},
        expires=int(time.time()) + PRP_TTL
    )
    store.PRPS[prp_id] = prp.model_dump()
    store.UNLOCKS[prp_id] = {"status": "pending"}
    return UnlockStartResponse(prp=prp)

@router.post("/unlock/settle")
def unlock_settle(body: UnlockSettleRequest):
    prp = store.PRPS.get(body.prp_id)
    if not prp:
        raise HTTPException(status_code=404, detail="prp_id not found")
    store.UNLOCKS[body.prp_id] = {
        "status": "paid",
        "settlement": SettlementRefs(preimage=body.preimage, txid=body.txid, settled_at=int(time.time())).model_dump()
    }
    return {"ok": True}

@router.post("/unlock/complete", response_model=UnlockTokenResponse)
def unlock_complete(body: UnlockCompleteRequest):
    state = store.UNLOCKS.get(body.prp_id)
    if not state:
        raise HTTPException(status_code=404, detail="prp_id not found")
    if state.get("status") != "paid":
        raise HTTPException(status_code=400, detail="payment not settled yet")
    token = hmac_token({
        "kind": "unlock",
        "claim_id_or_hash": body.claim_id_or_hash,
        "settlement": state["settlement"]
    }, ttl_secs=86400)
    return UnlockTokenResponse(token=token)
