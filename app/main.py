from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routes.auth import router as auth_router
from .routes.unlock import router as unlock_router
from .routes.claims import router as claims_router
from .routes.login_invoice import router as login_invoice_router

from app.oidc_discovery import router as oidc_router
from app.oidc_endpoints import router as oidc_endpoints_router

app = FastAPI(title="BTC DID — Stateless Auth API", version="0.1.0")

# OIDC discovery + endpoints
app.include_router(oidc_router)
app.include_router(oidc_endpoints_router)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# v1 routes
app.include_router(auth_router, prefix="/v1")
app.include_router(unlock_router, prefix="/v1")
app.include_router(claims_router, prefix="/v1")
app.include_router(login_invoice_router)  # Routes already have /v1 prefix

@app.get("/healthz")
def health():
    return {"ok": True}
