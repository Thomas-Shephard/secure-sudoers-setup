//! End-to-end integration tests that run the compiled `secure-sudoers` binary.

#![cfg(target_os = "linux")]

use assert_cmd::Command;
use ed25519_dalek::{Signer, SigningKey};

fn ss_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_secure-sudoers"))
}

use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use rand_core::OsRng;
use tempfile::TempDir;

const TEST_KERNEL_RELEASE_ENV: &str = "SECURE_SUDOERS_TEST_KERNEL_RELEASE";

fn generate_keypair() -> (SigningKey, [u8; 32]) {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key().to_bytes();
    (sk, vk)
}

fn write_pubkey_pem(dir: &TempDir, vk_bytes: &[u8; 32]) -> String {
    let b64 = secure_sudoers_common::util::bytes_to_base64(vk_bytes);
    let pem = format!(
        "-----BEGIN SECURE SUDOERS PUBLIC KEY-----\n{b64}\n-----END SECURE SUDOERS PUBLIC KEY-----\n"
    );
    let p = dir.path().join("pubkey.pem");
    std::fs::write(&p, pem).unwrap();
    p.to_str().unwrap().to_string()
}

fn write_signed_policy(dir: &TempDir, json: &str, sk: &SigningKey) -> String {
    let policy_path = dir.path().join("policy.json");
    std::fs::write(&policy_path, json).unwrap();
    let sig: ed25519_dalek::Signature = sk.sign(json.as_bytes());
    let sig_path = dir.path().join("policy.json.sig");
    std::fs::write(sig_path, sig.to_bytes()).unwrap();
    policy_path.to_str().unwrap().to_string()
}

const EMPTY_TOOLS_POLICY: &str = r#"{
  "version": "1.0",
  "serial": 1,
  "global_settings": {
    "admin_contact": "Contact: security@example.com"
  },
  "tools": {}
}"#;

#[test]
fn test_binary_rejects_kernel_below_4_19() {
    ss_cmd()
        .env(TEST_KERNEL_RELEASE_ENV, "4.18.20")
        .arg("sometool")
        .assert()
        .failure()
        .stderr(contains("requires Linux kernel 4.19 or newer"))
        .stderr(contains("Cannot load policy").not());
}

#[test]
fn test_binary_accepts_supported_kernel_release() {
    ss_cmd()
        .env(TEST_KERNEL_RELEASE_ENV, "4.19.0-200.el8")
        .env(
            "SECURE_SUDOERS_POLICY_PATH",
            "/nonexistent/path/policy.json",
        )
        .env("SECURE_SUDOERS_PUBKEY_PATH", "/dev/null")
        .arg("sometool")
        .assert()
        .failure()
        .stderr(contains("Cannot load policy"))
        .stderr(contains("requires Linux kernel 4.19 or newer").not());
}

#[test]
fn test_binary_missing_policy_exits_fatally() {
    ss_cmd()
        .env(
            "SECURE_SUDOERS_POLICY_PATH",
            "/nonexistent/path/policy.json",
        )
        .env("SECURE_SUDOERS_PUBKEY_PATH", "/dev/null")
        .arg("sometool")
        .assert()
        .failure()
        .stderr(contains("Cannot load policy"));
}

#[test]
fn test_binary_bad_signature_exits_fatally() {
    let dir = TempDir::new().unwrap();
    let (_sk, vk_bytes) = generate_keypair();
    let pubkey_path = write_pubkey_pem(&dir, &vk_bytes);

    let policy_path = dir.path().join("policy.json");
    std::fs::write(&policy_path, EMPTY_TOOLS_POLICY).unwrap();
    let bad_sig = vec![0xffu8; 64];
    std::fs::write(dir.path().join("policy.json.sig"), &bad_sig).unwrap();

    ss_cmd()
        .env("SECURE_SUDOERS_POLICY_PATH", policy_path.to_str().unwrap())
        .env("SECURE_SUDOERS_PUBKEY_PATH", &pubkey_path)
        .arg("sometool")
        .assert()
        .failure()
        .stderr(contains("Cannot load policy"));
}

#[test]
fn test_binary_tool_not_permitted_shows_denial_and_contact() {
    let dir = TempDir::new().unwrap();
    let (sk, vk_bytes) = generate_keypair();
    let pubkey_path = write_pubkey_pem(&dir, &vk_bytes);
    let policy_path = write_signed_policy(&dir, EMPTY_TOOLS_POLICY, &sk);

    ss_cmd()
        .env("SECURE_SUDOERS_POLICY_PATH", &policy_path)
        .env("SECURE_SUDOERS_PUBKEY_PATH", &pubkey_path)
        .arg("nonexistent_tool")
        .assert()
        .failure()
        .stderr(contains("Access denied"))
        .stderr(contains("Contact: security@example.com"));
}

#[test]
fn test_binary_direct_invocation_denied_tool() {
    let dir = TempDir::new().unwrap();
    let (sk, vk_bytes) = generate_keypair();
    let pubkey_path = write_pubkey_pem(&dir, &vk_bytes);
    let policy_path = write_signed_policy(&dir, EMPTY_TOOLS_POLICY, &sk);

    ss_cmd()
        .env("SECURE_SUDOERS_POLICY_PATH", &policy_path)
        .env("SECURE_SUDOERS_PUBKEY_PATH", &pubkey_path)
        .args(["nonexistent_tool", "somearg"])
        .assert()
        .failure()
        .stderr(contains("Access denied"));
}

#[test]
fn test_redaction_in_stdout_log() {
    let dir = TempDir::new().unwrap();
    let (sk, vk_bytes) = generate_keypair();
    let pubkey_path = write_pubkey_pem(&dir, &vk_bytes);

    let policy_json = r#"{
      "version": "1.0",
      "serial": 1,
      "global_settings": {
        "log_destination": "stdout",
        "log_format": "text",
        "admin_contact": "Contact: security@example.com"
      },
      "tools": {
        "apt": {
          "real_binary": "/bin/true",
          "help_description": "apt package manager (test stub)",
          "verbs": ["install"],
          "parameters": {
            "--password": { "type": "string", "sensitive": true }
          }
        }
      }
    }"#;

    let policy_path = write_signed_policy(&dir, policy_json, &sk);

    ss_cmd()
        .env("SECURE_SUDOERS_POLICY_PATH", &policy_path)
        .env("SECURE_SUDOERS_PUBKEY_PATH", &pubkey_path)
        .args(["apt", "install", "--password=SECRET"])
        .assert()
        .stdout(contains("[REDACTED]"))
        .stdout(contains("SECRET").not());
}

#[test]
fn test_binary_hash_failure_is_fatal_for_approved_command() {
    let dir = TempDir::new().unwrap();
    let (sk, vk_bytes) = generate_keypair();
    let pubkey_path = write_pubkey_pem(&dir, &vk_bytes);

    // Use a directory as the binary so hashing fails
    let non_regular_target = dir.path().join("not_a_binary_dir");
    std::fs::create_dir(&non_regular_target).unwrap();

    let policy_json = format!(
        r#"{{
  "version": "1.0",
  "serial": 1,
  "global_settings": {{
    "log_destination": "stdout",
    "log_format": "text",
    "admin_contact": "Contact: security@example.com"
  }},
  "tools": {{
    "noreadtrue": {{
      "real_binary": "{}",
      "help_description": "exec-only true",
      "verbs": [],
      "parameters": {{}}
    }}
  }}
}}"#,
        non_regular_target.to_string_lossy()
    );

    let policy_path = write_signed_policy(&dir, &policy_json, &sk);

    ss_cmd()
        .env("SECURE_SUDOERS_POLICY_PATH", &policy_path)
        .env("SECURE_SUDOERS_PUBKEY_PATH", &pubkey_path)
        .arg("noreadtrue")
        .assert()
        .failure()
        .stdout(contains("Command approved").not())
        .stderr(contains("Cannot compute binary hash"));
}

#[test]
fn test_binary_spoofing_event_includes_observed_binary_hash_when_available() {
    let dir = TempDir::new().unwrap();
    let (sk, vk_bytes) = generate_keypair();
    let pubkey_path = write_pubkey_pem(&dir, &vk_bytes);

    let true_path = if std::path::Path::new("/usr/bin/true").exists() {
        "/usr/bin/true"
    } else {
        "/bin/true"
    };
    let false_path = if std::path::Path::new("/usr/bin/false").exists() {
        "/usr/bin/false"
    } else {
        "/bin/false"
    };
    let spoofed_true = dir.path().join("true");
    std::fs::copy(false_path, &spoofed_true).unwrap();

    let expected_hash = {
        let mut cmd = Command::new("sha256sum");
        cmd.arg(&spoofed_true);
        let out = cmd.assert().success().get_output().stdout.clone();
        String::from_utf8(out)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_string()
    };

    let policy_json = format!(
        r#"{{
  "version": "1.0",
  "serial": 1,
  "global_settings": {{
    "log_destination": "stdout",
    "log_format": "json",
    "admin_contact": "Contact: security@example.com"
  }},
  "tools": {{
    "true": {{
      "real_binary": "{}",
      "help_description": "true command",
      "verbs": [],
      "parameters": {{}}
    }}
  }}
}}"#,
        true_path
    );

    let policy_path = write_signed_policy(&dir, &policy_json, &sk);

    ss_cmd()
        .env("SECURE_SUDOERS_POLICY_PATH", &policy_path)
        .env("SECURE_SUDOERS_PUBKEY_PATH", &pubkey_path)
        .env("SUDO_COMMAND", spoofed_true.to_string_lossy().to_string())
        .arg("true")
        .assert()
        .failure()
        .stdout(contains(expected_hash))
        .stderr(contains("Spoofing attempt detected"));
}
