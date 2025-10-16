from fastapi import APIRouter

router = APIRouter()

@router.get("/invoice")
def create_invoice():
    # TODO: replace with actual Lightning node call (LND / LNbits / NWC)
    return {"invoice": "lnbc1-test-placeholder-000000000000"}
