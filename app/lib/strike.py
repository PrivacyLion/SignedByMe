"""
Strike API client for Lightning payouts.

Non-blocking, idempotent payout support.
"""

import os
import httpx
import logging
from typing import Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger("strike")

STRIKE_API_BASE = "https://api.strike.me/v1"


class PayoutStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    PENDING = "pending"


@dataclass
class PayoutResult:
    status: PayoutStatus
    amount_sats: Optional[int] = None
    payment_id: Optional[str] = None
    error: Optional[str] = None
    
    def to_dict(self) -> dict:
        d = {"status": self.status.value}
        if self.amount_sats is not None:
            d["amount_sats"] = self.amount_sats
        if self.payment_id:
            d["payment_id"] = self.payment_id
        if self.error:
            d["error"] = self.error
        return d


# In-memory idempotency cache (session_id -> PayoutResult)
# In production, use Redis or DB
_payout_cache: dict[str, PayoutResult] = {}


def get_strike_api_key() -> Optional[str]:
    """Get Strike API key from environment."""
    return os.environ.get("STRIKE_API_KEY")


def is_strike_configured() -> bool:
    """Check if Strike is configured."""
    return bool(get_strike_api_key())


async def pay_invoice(
    bolt11: str,
    idempotency_key: str,
    amount_sats: int,
    description: Optional[str] = None
) -> PayoutResult:
    """
    Pay a BOLT11 invoice via Strike API.
    
    Args:
        bolt11: BOLT11 invoice string
        idempotency_key: Unique key (session_id) to prevent double-pays
        amount_sats: Expected amount (for logging/validation)
        description: Optional description for the payment
    
    Returns:
        PayoutResult with status and details
    """
    # Check idempotency cache first
    if idempotency_key in _payout_cache:
        logger.info(f"Payout already processed for {idempotency_key}")
        return _payout_cache[idempotency_key]
    
    api_key = get_strike_api_key()
    if not api_key:
        result = PayoutResult(
            status=PayoutStatus.SKIPPED,
            error="Strike API key not configured"
        )
        logger.warning("Strike payout skipped: no API key")
        return result
    
    # Mark as pending to prevent concurrent requests
    _payout_cache[idempotency_key] = PayoutResult(status=PayoutStatus.PENDING)
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Step 1: Create a payment quote for the invoice
            quote_response = await client.post(
                f"{STRIKE_API_BASE}/payment-quotes/lightning",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "lnInvoice": bolt11,
                    "descriptionHash": None
                }
            )
            
            if quote_response.status_code != 200 and quote_response.status_code != 201:
                error_msg = f"Quote failed: {quote_response.status_code} - {quote_response.text}"
                logger.error(error_msg)
                result = PayoutResult(
                    status=PayoutStatus.FAILED,
                    error=error_msg
                )
                _payout_cache[idempotency_key] = result
                return result
            
            quote_data = quote_response.json()
            quote_id = quote_data.get("paymentQuoteId")
            
            if not quote_id:
                error_msg = f"No quote ID in response: {quote_data}"
                logger.error(error_msg)
                result = PayoutResult(
                    status=PayoutStatus.FAILED,
                    error=error_msg
                )
                _payout_cache[idempotency_key] = result
                return result
            
            logger.info(f"Strike quote created: {quote_id}")
            
            # Step 2: Execute the payment
            pay_response = await client.patch(
                f"{STRIKE_API_BASE}/payment-quotes/{quote_id}/execute",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                }
            )
            
            if pay_response.status_code != 200:
                error_msg = f"Payment failed: {pay_response.status_code} - {pay_response.text}"
                logger.error(error_msg)
                result = PayoutResult(
                    status=PayoutStatus.FAILED,
                    error=error_msg
                )
                _payout_cache[idempotency_key] = result
                return result
            
            pay_data = pay_response.json()
            payment_id = pay_data.get("paymentId") or quote_id
            
            logger.info(f"Strike payment successful: {payment_id} ({amount_sats} sats)")
            
            result = PayoutResult(
                status=PayoutStatus.SUCCESS,
                amount_sats=amount_sats,
                payment_id=payment_id
            )
            _payout_cache[idempotency_key] = result
            return result
            
    except httpx.TimeoutException:
        error_msg = "Strike API timeout"
        logger.error(error_msg)
        result = PayoutResult(
            status=PayoutStatus.FAILED,
            error=error_msg
        )
        _payout_cache[idempotency_key] = result
        return result
        
    except Exception as e:
        error_msg = f"Strike error: {str(e)}"
        logger.exception(error_msg)
        result = PayoutResult(
            status=PayoutStatus.FAILED,
            error=error_msg
        )
        _payout_cache[idempotency_key] = result
        return result


async def get_account_balance() -> Optional[dict]:
    """Get Strike account balance (for admin dashboard)."""
    api_key = get_strike_api_key()
    if not api_key:
        return None
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"{STRIKE_API_BASE}/balances",
                headers={"Authorization": f"Bearer {api_key}"}
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"Failed to get Strike balance: {response.status_code}")
                return None
                
    except Exception as e:
        logger.exception(f"Error getting Strike balance: {e}")
        return None


def clear_idempotency_cache():
    """Clear the idempotency cache (for testing)."""
    _payout_cache.clear()
