use secure_sudoers_utils::modules::installer;

#[test]
fn test_sudoers_generation() {
    let tools = vec!["apt".to_string(), "systemctl".to_string()];
    let content = installer::sudoers_io::generate_sudoers_content(&tools);

    assert!(content.contains("/usr/local/bin/apt"));
    assert!(content.contains("/usr/local/bin/systemctl"));
    assert!(content.contains("ALL ALL=(root)"));
}

#[test]
fn test_crypto_flow() {
    use ed25519_dalek::{Signer, SigningKey, Verifier};
    use rand_core::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let message = b"test payload";
    let signature = signing_key.sign(message);

    assert!(verifying_key.verify(message, &signature).is_ok());
}
