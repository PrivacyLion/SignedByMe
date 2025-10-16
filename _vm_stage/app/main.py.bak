from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routes.auth import router as auth_router
from .routes.unlock import router as unlock_router
from .routes.claims import router as claims_router

app = FastAPI(title="BTC DID — Stateless Auth API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/v1")
app.include_router(unlock_router, prefix="/v1")
app.include_router(claims_router, prefix="/v1")

@app.get("/healthz")
def health():
    return {"ok": True}
