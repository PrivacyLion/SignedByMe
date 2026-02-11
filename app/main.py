from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path

from .routes.auth import router as auth_router
from .routes.unlock import router as unlock_router
from .routes.claims import router as claims_router
from .routes.enterprise import router as enterprise_router
from .routes.login_invoice import router as login_router
from .routes.roots import router as roots_router

from app.oidc_discovery import router as oidc_router
from app.oidc_endpoints import router as oidc_endpoints_router

app = FastAPI(title="BTC DID — Stateless Auth API", version="0.1.0")

# Static site directory
SITE_DIR = Path(__file__).resolve().parents[1] / "site"

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

# v1 routes - login_router FIRST to avoid auth.py /login/start conflict
app.include_router(login_router)  # Login invoice + DLC routes (has /v1 prefix in routes)
app.include_router(roots_router)  # Merkle root registry
app.include_router(auth_router, prefix="/v1")
app.include_router(unlock_router, prefix="/v1")
app.include_router(claims_router, prefix="/v1")
app.include_router(enterprise_router)  # Stateless enterprise login (routes have /v1 prefix)

@app.get("/healthz")
def health():
    return {"ok": True}


# Serve static site
@app.get("/")
def serve_index():
    index_path = SITE_DIR / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return {"message": "SignedByMe API", "docs": "/docs"}


# Mount static files (JS, CSS, etc.)
if SITE_DIR.exists():
    app.mount("/", StaticFiles(directory=str(SITE_DIR), html=True), name="static")
