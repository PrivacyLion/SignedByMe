from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes.login import router as login_router
from app.routes.invoice import router as invoice_router  # legacy for beta page button

app = FastAPI(title="BTC DID — Stateless Auth API", version="0.1.0")

ALLOWED_ORIGINS = [
    "https://beta.privacy-lion.com",
    "http://beta.privacy-lion.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/healthz")
def healthz():
    return {"ok": True}

app.include_router(login_router, prefix="")
app.include_router(invoice_router, prefix="")
