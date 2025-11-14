// dlc_oracle.rs
// Minimal “local oracle” implementation that returns real JSON (not JNI stubs).
// Uses std hashing as a placeholder; NOT cryptographic.

use std::fmt::Write as _;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

// --- helpers: hex + hashing ---

fn to_hex_u64(x: u64) -> String {
    let mut s = String::with_capacity(16);
    let _ = write!(&mut s, "{:016x}", x);
    s
}

fn hash_str(s: &str) -> u64 {
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

// --- JSON helpers ---

/// Naive JSON string escaper (only what we need here)
fn escape_json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"'  => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _    => out.push(ch),
        }
    }
    out
}

/// Pass through provided JSON if it looks like an object/array; else quote it.
/// This keeps your existing Android strings (payoutsJson/oracleJson) usable.
fn passthrough_json(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        trimmed.to_string()
    } else {
        format!("\"{}\"", escape_json_str(trimmed))
    }
}

// --- contract + signature JSON stubs ---

/// Build a deterministic “contract id” from inputs.
/// This **does not** implement real DLCs; it gives you a stable id to pass around.
pub fn create_dlc_contract_json(outcome: &str, payouts_json: &str, oracle_json: &str) -> String {
    // Derive a simple pseudo-id
    let seed = format!("{}|{}|{}", outcome, payouts_json, oracle_json);
    let cid = to_hex_u64(hash_str(&seed));

    // Echo inputs back in a structured JSON for easier debugging in the app
    format!(r#"{{
  "status": "ok",
  "kind": "dlc_contract",
  "contract_id": "{}",
  "outcome": "{}",
  "payouts": {},
  "oracle": {}
}}"#, cid, escape_json_str(outcome), passthrough_json(payouts_json), passthrough_json(oracle_json))
}

/// Produce a deterministic “oracle signature” for a given outcome.
/// This is **not** cryptographic; it’s just a placeholder so you can
/// round-trip end-to-end and later swap in a real Schnorr/Taproot sig.
pub fn sign_dlc_outcome_json(outcome: &str) -> String {
    let sig_seed = format!("oracle|{}", outcome);
    let sig = to_hex_u64(hash_str(&sig_seed));
    format!(r#"{{
  "status": "ok",
  "kind": "dlc_oracle_signature",
  "outcome": "{}",
  "signature": "{}"
}}"#, escape_json_str(outcome), sig)
}

// --- minimal Oracle stub for wiring & tests ---

#[derive(Debug, Clone)]
pub struct Oracle {
    pub name: String,
    pub pubkey_hex: String,
}

impl Oracle {
    pub fn new(name: &str, pubkey_hex: &str) -> Self {
        Self { name: name.to_string(), pubkey_hex: pubkey_hex.to_string() }
    }

    /// Return our placeholder/local oracle used by the Android demo.
    pub fn local() -> Self {
        // Keep this as a placeholder; swap to your real 33-byte compressed key later.
        // If you prefer to match the Kotlin TODO, you can switch to "deadbeef".
        Self::new("local_oracle", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    }

    /// Stub “signature” so we can confirm round-trip without crypto yet.
    pub fn sign_outcome_stub(&self, outcome: &str) -> String {
        let seed = format!("{}|{}", self.name, outcome);
        to_hex_u64(hash_str(&seed))
    }
}

// Convenience exports so JNI can call through.
pub fn local_oracle_name() -> String { Oracle::local().name }
pub fn local_oracle_pubkey_hex() -> String { Oracle::local().pubkey_hex }
pub fn local_oracle_sign_outcome_stub(outcome: &str) -> String {
    Oracle::local().sign_outcome_stub(outcome)
}

// --- JNI-facing thin wrappers expected by lib.rs ---

pub fn oracle_pubkey_hex() -> String {
    local_oracle_pubkey_hex()
}

pub fn oracle_sign_outcome(outcome: &str) -> String {
    local_oracle_sign_outcome_stub(outcome)
}
