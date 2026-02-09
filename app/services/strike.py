"""
Strike API Integration for Enterprise Auto-Payments

Enterprise registers their Strike API key once.
When users log in, we auto-pay the invoice via Strike.
"""
import httpx
import hashlib
import time
from typing import Optional
from pydantic import BaseModel


STRIKE_API_BASE = "https://api.strike.me/v1"


class StrikePaymentResult(BaseModel):
    """Result of a Strike payment attempt"""
    success: bool
    payment_id: Optional[str] = None
    preimage: Optional[str] = None
    error: Optional[str] = None
    amount_sats: Optional[int] = None


class StrikeClient:
    """
    Strike API client for Lightning payments.
    
    Docs: https://docs.strike.me/api/
    """
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
    
    async def pay_invoice(self, bolt11: str) -> StrikePaymentResult:
        """
        Pay a BOLT11 invoice via Strike API.
        
        Strike flow:
        1. POST /v1/payment-quotes/lightning - Get quote
        2. PATCH /v1/payment-quotes/{id}/execute - Execute payment
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Step 1: Create payment quote
            quote_resp = await client.post(
                f"{STRIKE_API_BASE}/payment-quotes/lightning",
                headers=self.headers,
                json={
                    "lnInvoice": bolt11,
                    "sourceCurrency": "BTC"  # Pay from BTC balance
                }
            )
            
            if quote_resp.status_code != 200:
                return StrikePaymentResult(
                    success=False,
                    error=f"Quote failed: {quote_resp.status_code} - {quote_resp.text}"
                )
            
            quote = quote_resp.json()
            quote_id = quote.get("paymentQuoteId")
            
            if not quote_id:
                return StrikePaymentResult(
                    success=False,
                    error="No quote ID in response"
                )
            
            # Step 2: Execute payment
            exec_resp = await client.patch(
                f"{STRIKE_API_BASE}/payment-quotes/{quote_id}/execute",
                headers=self.headers
            )
            
            if exec_resp.status_code not in (200, 202):
                return StrikePaymentResult(
                    success=False,
                    error=f"Execute failed: {exec_resp.status_code} - {exec_resp.text}"
                )
            
            result = exec_resp.json()
            
            return StrikePaymentResult(
                success=True,
                payment_id=quote_id,
                preimage=result.get("preimage"),  # Strike returns this on success
                amount_sats=int(float(quote.get("amount", {}).get("amount", 0)) * 100_000_000)
            )
    
    async def get_balance(self) -> dict:
        """Get account balances."""
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{STRIKE_API_BASE}/balances",
                headers=self.headers
            )
            if resp.status_code != 200:
                return {"error": resp.text}
            return resp.json()
    
    async def validate_key(self) -> bool:
        """Check if API key is valid."""
        try:
            balance = await self.get_balance()
            return "error" not in balance
        except Exception:
            return False


# =============================================================================
# Enterprise Payment Registry
# =============================================================================

# In production, this would be encrypted storage or a secrets manager
# For now, in-memory (lost on restart) + shelve for persistence
_enterprise_keys: dict[str, str] = {}


def register_enterprise_strike(enterprise_id: str, strike_api_key: str):
    """
    Register an enterprise's Strike API key.
    Called once during enterprise onboarding.
    """
    _enterprise_keys[enterprise_id] = strike_api_key


def get_enterprise_strike_client(enterprise_id: str) -> Optional[StrikeClient]:
    """Get Strike client for an enterprise."""
    api_key = _enterprise_keys.get(enterprise_id)
    if not api_key:
        return None
    return StrikeClient(api_key)


async def auto_pay_login(enterprise_id: str, bolt11: str) -> StrikePaymentResult:
    """
    Auto-pay a login invoice for an enterprise.
    
    Returns payment result with preimage on success.
    """
    client = get_enterprise_strike_client(enterprise_id)
    if not client:
        return StrikePaymentResult(
            success=False,
            error=f"No Strike API configured for enterprise: {enterprise_id}"
        )
    
    return await client.pay_invoice(bolt11)
