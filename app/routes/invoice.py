from fastapi import APIRouter
from uuid import uuid4
from pathlib import Path
import hashlib, shelve, time

router = APIRouter(prefix="/v1", tags=["legacy"])

PROJECT_ROOT = Path(__file__).resolve().parents[2]
VAR_DIR = PROJECT_ROOT / "var"
VAR_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = VAR_DIR / "login_challenges.db"

@router.get("/invoice")
def legacy_invoice():
    challenge_id = f"lc_{uuid4().hex}"
    pr = "lnbc1-test-placeholder-" + uuid4().hex[:16]
    payment_hash = hashlib.sha256(pr.encode("utf-8")).hexdigest()

    rec = {
        "did_pubkey": "legacy-ui",
        "lightning_address": "legacy@client",
        "amount_sats": 21,
        "invoice": pr,
        "payment_hash": payment_hash,
        "status": "pending",
        "created_at": int(time.time()),
        "paid_at": None,
    }
    with shelve.open(str(DB_PATH)) as db:
        db[challenge_id] = rec

    return {
        "login_challenge_id": challenge_id,
        "invoice": pr,
        "payment_hash": payment_hash,
        "expires_in_sec": 600,
    }
