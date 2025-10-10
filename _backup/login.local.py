from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from uuid import uuid4
from pathlib import Path
import hashlib, shelve, time

router = APIRouter(prefix="/v1", tags=["login"])

# simple on-disk store so it works across multiple uvicorn workers
PROJECT_ROOT = Path(__file__).resolve().parents[2]   # ~/btc_did_api
VAR_DIR = PROJECT_ROOT / "var"
VAR_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = VAR_DIR / "login_challenges.db"

class StartLoginBody(BaseModel):
    did_pubkey: str
    lightning_address: str   # e.g. name@walletdomain (Cash App or other)
    amount_sats: int = 21    # tiny “prove-you-control” tip

@router.post("/login/start")
def login_start(body: StartLoginBody):
    """
    EA -> SA: start login by paying the user (EA-initiated).
    For now, we return a placeholder invoice but the route shape matches the roadmap:
      - SA would resolve the user's Lightning Address (LNURL-pay) to fetch an invoice
      - SA returns login_challenge_id + invoice + payment_hash to the EA
    """
    if body.amount_sats <= 0:
        raise HTTPException(400, "amount_sats must be > 0")

    # --- placeholder invoice & payment_hash (wire shape only) ---
    challenge_id = f"lc_{uuid4().hex}"
    pr = "lnbc1-test-placeholder-" + uuid4().hex[:16]
    payment_hash = hashlib.sha256(pr.encode("utf-8")).hexdigest()

    record = {
        "did_pubkey": body.did_pubkey,
        "lightning_address": body.lightning_address,
        "amount_sats": body.amount_sats,
        "invoice": pr,
        "payment_hash": payment_hash,
        "status": "pending",
        "created_at": int(time.time()),
    }

    with shelve.open(str(DB_PATH)) as db:
        db[challenge_id] = record

    return {
        "login_challenge_id": challenge_id,
        "invoice": pr,
        "payment_hash": payment_hash,
        "expires_in_sec": 600,
    }
