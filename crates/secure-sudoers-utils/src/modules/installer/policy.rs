use crate::modules::keys::load_verifying_key;
use ed25519_dalek::{Signature, Verifier};
use secure_sudoers_common::error::Error;
use secure_sudoers_common::models::SecureSudoersPolicy;

pub(super) fn load_policy(path: &str) -> Result<SecureSudoersPolicy, Error> {
    let bytes =
        std::fs::read(path).map_err(|e| Error::IoContext(format!("Cannot read {path}"), e))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::System(format!("Invalid policy JSON at {path}: {e}")))
}

pub(super) fn load_policy_with_verified_signature(
    policy_path: &str,
    public_key_path: &str,
) -> Result<SecureSudoersPolicy, Error> {
    let policy_bytes = std::fs::read(policy_path)
        .map_err(|e| Error::IoContext(format!("Cannot read {policy_path}"), e))?;
    verify_policy_signature(policy_path, &policy_bytes, public_key_path)?;
    let mut policy: SecureSudoersPolicy = serde_json::from_slice(&policy_bytes)
        .map_err(|e| Error::System(format!("Invalid policy JSON at {policy_path}: {e}")))?;
    policy.validate()?;
    Ok(policy)
}

fn verify_policy_signature(
    policy_path: &str,
    policy_bytes: &[u8],
    public_key_path: &str,
) -> Result<(), Error> {
    let verifying_key = load_verifying_key(public_key_path)?;
    let sig_path = format!("{policy_path}.sig");
    let sig_bytes = std::fs::read(&sig_path)
        .map_err(|e| Error::IoContext(format!("Cannot read policy signature {sig_path}"), e))?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        Error::Validation(format!(
            "Policy signature must be 64 bytes (got {})",
            sig_bytes.len()
        ))
    })?;
    verifying_key
        .verify(policy_bytes, &Signature::from_bytes(&sig_arr))
        .map_err(|e| {
            Error::Security(format!(
                "Policy signature verification failed for {policy_path}: {e}"
            ))
        })?;
    Ok(())
}
