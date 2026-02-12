#!/usr/bin/env python3
"""E2E test for login flow with test payment_hash"""
import json
import urllib.request

# Create session
print("Creating session...")
req = urllib.request.Request(
    "http://127.0.0.1:8000/v1/login/start",
    data=b'{"enterprise":"AcmeCorp","amount_sats":500}',
    headers={"Content-Type": "application/json", "X-API-Key": "acme_sk_test_abc123"}
)
r = json.loads(urllib.request.urlopen(req).read())
print(f"Session: {r['session_id']}")

# Build request
d = {
    "session_id": r["session_id"],
    "enterprise": "AcmeCorp",
    "amount_sats": 500,
    "did": "did:btcr:00",
    "invoice": "lnbc1",
    "payment_hash_hex": "0" * 64,
    "stwo_proof": json.dumps({
        "version": "stwo-real-1",
        "public_inputs": {
            "schema_version": 4,
            "expires_at": 9999999999,
            "amount_sats": 500,
            "ea_domain": "AcmeCorp"
        },
        "proof": "00"
    })
}

# Submit
print("Submitting invoice...")
req2 = urllib.request.Request(
    "http://127.0.0.1:8000/v1/login/invoice",
    data=json.dumps(d).encode(),
    headers={"Content-Type": "application/json"}
)
resp = json.loads(urllib.request.urlopen(req2).read())
print(json.dumps(resp, indent=2))
