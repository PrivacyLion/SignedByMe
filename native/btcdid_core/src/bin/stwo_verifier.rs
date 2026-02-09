// stwo_verifier.rs
// CLI tool to verify STWO identity proofs
// Used by the API server on the VPS

use std::io::{self, Read};
use std::process::ExitCode;

#[cfg(feature = "real-stwo")]
use btcdid_core::stwo_real::verify_proof_json;

fn main() -> ExitCode {
    // Read proof JSON from stdin
    let mut input = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut input) {
        eprintln!("Error reading stdin: {}", e);
        return ExitCode::from(2);
    }

    let input = input.trim();
    if input.is_empty() {
        eprintln!("Error: Empty input. Provide proof JSON via stdin.");
        return ExitCode::from(2);
    }

    #[cfg(feature = "real-stwo")]
    {
        match verify_proof_json(input) {
            Ok(true) => {
                println!("VALID");
                ExitCode::SUCCESS
            }
            Ok(false) => {
                println!("INVALID");
                ExitCode::from(1)
            }
            Err(e) => {
                eprintln!("ERROR: {}", e);
                ExitCode::from(2)
            }
        }
    }

    #[cfg(not(feature = "real-stwo"))]
    {
        eprintln!("Error: Built without real-stwo feature");
        ExitCode::from(2)
    }
}
