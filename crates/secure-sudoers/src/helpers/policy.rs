use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use secure_sudoers_common::error::Error;
use secure_sudoers_common::models::SecureSudoersPolicy;

const PUBLIC_KEY_PATH: &str = "/etc/secure-sudoers/secure_sudoers_public_key.pem";

pub fn load_policy(path: &str) -> Result<SecureSudoersPolicy, Error> {
    #[cfg(debug_assertions)]
    let pubkey_path =
        std::env::var("SECURE_SUDOERS_PUBKEY_PATH").unwrap_or_else(|_| PUBLIC_KEY_PATH.to_string());
    #[cfg(not(debug_assertions))]
    let pubkey_path = PUBLIC_KEY_PATH.to_string();
    load_policy_with_pubkey(path, &pubkey_path)
}

pub(crate) fn load_policy_with_pubkey(
    path: &str,
    pubkey_path: &str,
) -> Result<SecureSudoersPolicy, Error> {
    let policy_bytes = std::fs::read(path)
        .map_err(|e| Error::IoContext(format!("Failed to read policy {path}"), e))?;

    let pubkey_bytes =
        secure_sudoers_common::util::read_pem_bytes(pubkey_path, "SECURE SUDOERS PUBLIC KEY")?;
    let pubkey_arr: [u8; 32] = pubkey_bytes.as_slice().try_into().map_err(|_| {
        Error::Validation("Integrity failure: public key must be 32 bytes".to_string())
    })?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_arr)
        .map_err(|e| Error::Validation(format!("Integrity failure: invalid public key: {e}")))?;

    let sig_path = format!("{path}.sig");
    let sig_bytes = std::fs::read(&sig_path).map_err(|e| {
        Error::IoContext(
            format!("Integrity failure: policy signature file {sig_path} missing or unreadable"),
            e,
        )
    })?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        Error::Validation(format!(
            "Integrity failure: signature must be 64 bytes (got {})",
            sig_bytes.len()
        ))
    })?;
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key
        .verify(&policy_bytes, &signature)
        .map_err(|e| {
            Error::Security(format!(
                "Integrity failure: policy signature verification failed for {path}: {e}"
            ))
        })?;

    let mut policy: SecureSudoersPolicy = serde_json::from_slice(&policy_bytes)
        .map_err(|e| Error::Parse(format!("Failed to parse validated policy JSON: {e}")))?;

    policy
        .validate()
        .map_err(|e| Error::Validation(format!("Policy validation failed: {e}")))?;
    Ok(policy)
}
