from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from uuid import uuid4
from pathlib import Path
import hashlib, shelve, time
from typing import Optional

router = APIRouter(prefix="/v1", tags=["login"])

PROJECT_ROOT = Path(__file__).resolve().parents[2]
VAR_DIR = PROJECT_ROOT / "var"
VAR_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = VAR_DIR / "login_challenges.db"

class StartLoginBody(BaseModel):
    did_pubkey: str
    amount_sats: int = Field(21, gt=0)
    # Preferred: client provides real BOLT-11 + payment_hash (p-tag)
    invoice: Optional[str] = None
    payment_hash: Optional[str] = None
    # Legacy/demo path (kept for compatibility)
    lightning_address: Optional[str] = None

class VerifyBody(BaseModel):
    payment_hash: str    # 64-hex
    preimage: str        # 64-hex; server checks sha256(preimage) == payment_hash

@router.post("/login/start")
def login_start(body: StartLoginBody):
    cid = f"lc_{uuid4().hex}"
    if body.invoice and body.payment_hash:
        pr = body.invoice
        ph = body.payment_hash.lower()
        if len(ph) != 64 or any(c not in "0123456789abcdef" for c in ph):
            raise HTTPException(400, "payment_hash must be 64 hex chars")
    else:
        # Legacy scaffold for demos: non-settleable placeholder
        pr = "lnbc1-test-placeholder-" + uuid4().hex[:16]
        ph = hashlib.sha256(pr.encode()).hexdigest()

    rec = {
        "did_pubkey": body.did_pubkey,
        "amount_sats": body.amount_sats,
        "invoice": pr,
        "payment_hash": ph,
        "status": "pending",
        "created_at": int(time.time()),
        "paid_at": None,
    }
    with shelve.open(str(DB_PATH)) as db:
        db[cid] = rec

    return {"login_challenge_id": cid, "invoice": pr, "payment_hash": ph, "expires_in_sec": 600}

@router.post("/login/verify")
def login_verify(body: VerifyBody):
    pre = body.preimage.lower()
    if len(pre) != 64 or any(c not in "0123456789abcdef" for c in pre):
        raise HTTPException(400, "preimage must be 64 hex chars")
    computed = hashlib.sha256(bytes.fromhex(pre)).hexdigest()

    with shelve.open(str(DB_PATH), writeback=True) as db:
        for k in db.keys():
            rec = db[k]
            if rec.get("payment_hash") == body.payment_hash.lower():
                if computed != rec["payment_hash"]:
                    raise HTTPException(400, "preimage does not match payment_hash")
                if rec.get("status") != "paid":
                    rec["status"] = "paid"
                    rec["paid_at"] = int(time.time())
                    db[k] = rec
                return {"ok": True, "login_challenge_id": k, "status": "paid"}
    raise HTTPException(404, "payment_hash not found")

@router.get("/login/{challenge_id}")
def login_status(challenge_id: str):
    """
    Return the current status of a login challenge so UIs can poll.
    Response: {status, payment_hash, created_at, paid_at, invoice?}
    """
    with shelve.open(str(DB_PATH)) as db:
        rec = db.get(challenge_id)
        if not rec:
            raise HTTPException(404, "challenge_id not found")
        return {
            "status": rec.get("status"),
            "payment_hash": rec.get("payment_hash"),
            "created_at": rec.get("created_at"),
            "paid_at": rec.get("paid_at"),
            "invoice": rec.get("invoice"),
        }
