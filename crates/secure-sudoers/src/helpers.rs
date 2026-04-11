pub mod binding;
pub mod invocation;
pub mod policy;
pub mod redaction;
mod sudo_command;

#[cfg(test)]
use binding::verify_sudo_command_binding_internal;
#[cfg(test)]
use ed25519_dalek::Signature;
#[cfg(test)]
use invocation::{parse_invocation, parse_invocation_internal, parse_proc_self_cmdline_bytes};
#[cfg(test)]
use policy::load_policy_with_pubkey;
#[cfg(test)]
use redaction::redact_args;
#[cfg(test)]
use std::path::Path;
#[cfg(test)]
use sudo_command::{
    SudoCommandTokenError, delegated_command_token_from_sudo_command,
    split_sudo_command_prefix_tokens,
};

#[cfg(test)]
mod tests {
    use super::*;
    use secure_sudoers_common::models::{ParameterConfig, ParameterType, UnauthorizedAuditMode};
    use secure_sudoers_common::testing::fixtures::{args as argv, make_policy};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn test_redact_args_clustered_with_separate_value() {
        let mut policy = make_policy();
        if let Some(tool) = policy.tools.get_mut("apt") {
            tool.parameters
                .insert("-p".into(), ParameterConfig::string().sensitive());
        }
        let args = argv(&["install", "-vp", "secret", "curl"]);
        let redacted = redact_args(&args, &policy, "apt");
        assert_eq!(redacted, argv(&["install", "-vp", "[REDACTED]", "curl"]));
    }

    #[test]
    fn test_redact_args_clustered_short_flag() {
        let mut policy = make_policy();
        if let Some(tool) = policy.tools.get_mut("apt") {
            tool.parameters
                .insert("-p".into(), ParameterConfig::string().sensitive());
        }
        let args = argv(&["install", "-vpSECRET", "curl"]);
        let redacted = redact_args(&args, &policy, "apt");
        assert_eq!(redacted, argv(&["install", "-vp[REDACTED]", "curl"]));
    }

    #[test]
    fn test_redact_args_attached_short_flag() {
        let mut policy = make_policy();
        if let Some(tool) = policy.tools.get_mut("apt") {
            tool.parameters
                .insert("-p".into(), ParameterConfig::string().sensitive());
        }
        let args = argv(&["install", "-pSECRET", "curl"]);
        let redacted = redact_args(&args, &policy, "apt");
        assert_eq!(redacted, argv(&["install", "-p[REDACTED]", "curl"]));
    }

    #[test]
    fn test_redact_args_unauthorized_keys_only_attached() {
        let mut policy = make_policy();
        policy.global_settings.unauthorized_audit_mode = UnauthorizedAuditMode::KeysOnly;
        let args = argv(&["-pSECRET", "-abc", "--longer"]);
        let redacted = redact_args(&args, &policy, "unknown");
        assert_eq!(redacted, vec!["-p[REDACTED]", "-a[REDACTED]", "--longer"]);
    }

    #[test]
    fn test_redact_args_unauthorized_minimal() {
        let mut policy = make_policy();
        policy.global_settings.unauthorized_audit_mode = UnauthorizedAuditMode::Minimal;
        let args = argv(&["--pass", "secret", "pos"]);
        let redacted = redact_args(&args, &policy, "unknown");
        assert_eq!(redacted, vec!["[3 arguments suppressed]"]);
    }

    #[test]
    fn test_redact_args_unauthorized_keys_only() {
        let mut policy = make_policy();
        policy.global_settings.unauthorized_audit_mode = UnauthorizedAuditMode::KeysOnly;
        let args = argv(&["--pass=secret", "-f", "pos"]);
        let redacted = redact_args(&args, &policy, "unknown");
        assert_eq!(redacted, vec!["--pass=[REDACTED]", "-f", "[REDACTED]"]);
    }

    #[test]
    fn test_redact_args_unauthorized_full() {
        let mut policy = make_policy();
        policy.global_settings.unauthorized_audit_mode = UnauthorizedAuditMode::Full;
        let args = argv(&["--pass", "secret"]);
        let redacted = redact_args(&args, &policy, "unknown");
        assert_eq!(redacted, args);
    }

    #[test]
    fn test_redact_args_sensitive_positional() {
        let mut policy = make_policy();
        if let Some(tool) = policy.tools.get_mut("apt") {
            tool.positional = Some(ParameterConfig::string().sensitive());
        }
        let args = argv(&["install", "secret-pkg", "-y"]);
        let redacted = redact_args(&args, &policy, "apt");

        assert_eq!(redacted, argv(&["[REDACTED]", "[REDACTED]", "-y"]));
    }

    #[test]
    fn test_redact_args_sensitive_positional_after_double_dash() {
        let mut policy = make_policy();
        if let Some(tool) = policy.tools.get_mut("apt") {
            tool.positional = Some(ParameterConfig::string().sensitive());
        }
        let args = argv(&["install", "-y", "--", "-secret-token", "--api-key", "value"]);
        let redacted = redact_args(&args, &policy, "apt");

        assert_eq!(
            redacted,
            argv(&[
                "[REDACTED]",
                "-y",
                "--",
                "[REDACTED]",
                "[REDACTED]",
                "[REDACTED]"
            ])
        );
    }

    #[test]
    fn test_redact_args_sensitive_positional_starting_with_hyphen() {
        let mut policy = make_policy();
        if let Some(tool) = policy.tools.get_mut("apt") {
            tool.positional = Some(ParameterConfig::string().sensitive());
        }
        let args = argv(&["install", "-secret-token", "-y"]);
        let redacted = redact_args(&args, &policy, "apt");

        assert_eq!(redacted, argv(&["[REDACTED]", "[REDACTED]", "-y"]));
    }

    #[test]
    fn test_redact_args_unknown_long_flag_equals_redacts_value() {
        let policy = make_policy();
        let args = argv(&["install", "--api-key=SECRET_VALUE", "curl"]);
        let redacted = redact_args(&args, &policy, "apt");

        assert_eq!(redacted, argv(&["install", "--api-key=[REDACTED]", "curl"]));
    }

    #[test]
    fn test_redact_args_unknown_long_flag_separate_value_redacts_next_arg() {
        let policy = make_policy();
        let args = argv(&["install", "--api-key", "-SECRET_VALUE", "curl"]);
        let redacted = redact_args(&args, &policy, "apt");

        assert_eq!(
            redacted,
            argv(&["install", "--api-key", "[REDACTED]", "curl"])
        );
    }

    #[test]
    fn test_redact_args_with_equals_syntax() {
        let mut policy = make_policy();
        if let Some(tool) = policy.tools.get_mut("apt") {
            tool.parameters.insert(
                "--password".to_string(),
                ParameterConfig {
                    param_type: ParameterType::String,
                    sensitive: true,
                    regex: None,
                    compiled_regex: None,
                    allowed: None,
                    disallowed: None,
                    help: None,
                },
            );
        }

        let raw_args = argv(&[
            "install",
            "--password=SECRET",
            "--password",
            "SECRET2",
            "curl",
        ]);
        let redacted = redact_args(&raw_args, &policy, "apt");

        assert_eq!(
            redacted,
            argv(&[
                "install",
                "--password=[REDACTED]",
                "--password",
                "[REDACTED]",
                "curl"
            ])
        );
    }

    #[test]
    fn parse_proc_self_cmdline_bytes_preserves_empty_arguments() {
        let parsed = parse_proc_self_cmdline_bytes(b"tool\0\0arg\0").unwrap();
        assert_eq!(parsed, argv(&["tool", "", "arg"]));
    }

    #[test]
    fn parse_proc_self_cmdline_bytes_trims_only_final_terminator() {
        let parsed = parse_proc_self_cmdline_bytes(b"tool\0\0").unwrap();
        assert_eq!(parsed, argv(&["tool", ""]));
    }

    #[test]
    fn split_sudo_command_prefix_preserves_backslash_in_single_quotes() {
        let parsed = split_sudo_command_prefix_tokens("'a\\b' rest", 2).unwrap();
        assert_eq!(parsed, argv(&["a\\b", "rest"]));
    }

    #[test]
    fn delegated_command_token_reports_missing_wrapper_subcommand() {
        let parsed = delegated_command_token_from_sudo_command("/usr/local/bin/secure-sudoers");
        assert_eq!(parsed, Err(SudoCommandTokenError::MissingDelegatedCommand));
    }

    #[test]
    fn direct_invocation_extracts_tool_and_args() {
        let (tool, args) =
            parse_invocation(&argv(&["secure-sudoers", "apt", "-y", "install"])).unwrap();
        assert_eq!(tool, "apt");
        assert_eq!(args, argv(&["-y", "install"]));
    }

    #[test]
    fn symlink_invocation_uses_basename_as_tool() {
        let (tool, args) =
            parse_invocation(&argv(&["/usr/local/bin/apt", "-y", "install", "curl"])).unwrap();
        assert_eq!(tool, "apt");
        assert_eq!(args, argv(&["-y", "install", "curl"]));
    }

    #[test]
    fn direct_invocation_without_args_returns_empty() {
        let (tool, args) = parse_invocation(&argv(&["secure-sudoers"])).unwrap();
        assert_eq!(tool, "");
        assert!(args.is_empty());
    }

    #[test]
    fn symlink_invocation_without_args_returns_empty_args() {
        let (tool, args) = parse_invocation(&argv(&["/usr/bin/tail"])).unwrap();
        assert_eq!(tool, "tail");
        assert!(args.is_empty());
    }

    #[test]
    fn underscore_variant_treated_as_direct() {
        let (tool, args) =
            parse_invocation(&argv(&["secure_sudoers", "systemctl", "status"])).unwrap();
        assert_eq!(tool, "systemctl");
        assert_eq!(args, argv(&["status"]));
    }

    #[test]
    fn sudo_command_prioritized_and_matches() {
        let true_path = if Path::new("/usr/bin/true").exists() {
            "/usr/bin/true"
        } else {
            "/bin/true"
        };
        let env = |k: &str| -> Option<String> {
            if k == "SUDO_COMMAND" {
                Some(format!("{true_path} install"))
            } else {
                None
            }
        };
        let (tool, args) =
            parse_invocation_internal(&argv(&["secure-sudoers", "true", "install"]), env).unwrap();
        assert_eq!(tool, "true");
        assert_eq!(args, argv(&["install"]));
    }

    #[test]
    fn sudo_command_mismatch_detected() {
        let env = |k: &str| -> Option<String> {
            if k == "SUDO_COMMAND" {
                Some("/usr/bin/evil".to_string())
            } else {
                None
            }
        };
        let result = parse_invocation_internal(&argv(&["secure-sudoers", "apt", "install"]), env);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Spoofing attempt detected")
        );
    }

    #[test]
    fn sudo_command_missing_falls_back() {
        let env = |_: &str| -> Option<String> { None };
        let (tool, _) = parse_invocation_internal(&argv(&["/usr/bin/tail", "file"]), env).unwrap();
        assert_eq!(tool, "tail");
    }

    #[test]
    fn sudo_command_missing_falls_back_to_subcommand_basename() {
        let dir = tempfile::TempDir::new().unwrap();
        let tool_path = dir.path().join("custom-tool");
        std::fs::write(&tool_path, b"#!/bin/sh\nexit 0\n").unwrap();

        let env = |_: &str| -> Option<String> { None };
        let (tool, args) = parse_invocation_internal(
            &argv(&[
                "secure-sudoers",
                tool_path.to_str().unwrap(),
                "--flag",
                "value",
            ]),
            env,
        )
        .unwrap();
        assert_eq!(tool, "custom-tool");
        assert_eq!(args, argv(&["--flag", "value"]));
    }

    #[test]
    fn sudo_command_basename_extraction() {
        let dir = tempfile::TempDir::new().unwrap();
        let tool_path = dir.path().join("apt");
        std::fs::write(&tool_path, b"#!/bin/sh\nexit 0\n").unwrap();
        let mut perms = std::fs::metadata(&tool_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&tool_path, perms).unwrap();

        let env = |k: &str| -> Option<String> {
            if k == "SUDO_COMMAND" {
                Some(format!("{} install", tool_path.to_string_lossy()))
            } else {
                None
            }
        };
        let (tool, _) = parse_invocation_internal(
            &argv(&["secure-sudoers", tool_path.to_str().unwrap(), "install"]),
            env,
        )
        .unwrap();
        assert_eq!(tool, "apt");
    }

    #[test]
    fn sudo_command_with_wrapper_skipped() {
        let true_path = if Path::new("/usr/bin/true").exists() {
            "/usr/bin/true"
        } else {
            "/bin/true"
        };
        let env = |k: &str| -> Option<String> {
            if k == "SUDO_COMMAND" {
                Some(format!("/usr/local/bin/secure-sudoers {true_path} install"))
            } else {
                None
            }
        };
        let (tool, _) =
            parse_invocation_internal(&argv(&["secure-sudoers", "true", "install"]), env).unwrap();
        assert_eq!(tool, "true");
    }

    #[test]
    fn sudo_command_wrapper_without_subcommand_fails_closed() {
        let env = |k: &str| -> Option<String> {
            if k == "SUDO_COMMAND" {
                Some("/usr/local/bin/secure-sudoers".to_string())
            } else {
                None
            }
        };

        let result = parse_invocation_internal(&argv(&["secure-sudoers", "true", "install"]), env);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Spoofing attempt detected")
        );
    }

    #[test]
    fn sudo_command_quoted_tool_path_is_parsed_correctly() {
        let dir = tempfile::TempDir::new().unwrap();
        let spaced_dir = dir.path().join("dir with space");
        std::fs::create_dir_all(&spaced_dir).unwrap();
        let tool_path = spaced_dir.join("apt");
        std::fs::write(&tool_path, b"#!/bin/sh\nexit 0\n").unwrap();
        let mut perms = std::fs::metadata(&tool_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&tool_path, perms).unwrap();

        let sudo_cmd = format!("\"{}\" install", tool_path.to_string_lossy());
        let env = |k: &str| -> Option<String> {
            if k == "SUDO_COMMAND" {
                Some(sudo_cmd.clone())
            } else {
                None
            }
        };

        let (tool, args) = parse_invocation_internal(
            &argv(&[
                "secure-sudoers",
                tool_path.to_str().unwrap(),
                "install",
                "curl",
            ]),
            env,
        )
        .unwrap();

        assert_eq!(tool, "apt");
        assert_eq!(args, argv(&["install", "curl"]));
    }

    #[test]
    fn sudo_command_with_malformed_trailing_args_still_parses_tool_prefix() {
        let true_path = if Path::new("/usr/bin/true").exists() {
            "/usr/bin/true"
        } else {
            "/bin/true"
        };
        let sudo_cmd = format!("{true_path} install \"unterminated");
        let env = |k: &str| -> Option<String> {
            if k == "SUDO_COMMAND" {
                Some(sudo_cmd.clone())
            } else {
                None
            }
        };
        let (tool, args) =
            parse_invocation_internal(&argv(&["secure-sudoers", "true", "install"]), env).unwrap();
        assert_eq!(tool, "true");
        assert_eq!(args, argv(&["install"]));
    }

    #[test]
    fn sudo_command_with_malformed_second_token_still_parses_non_wrapper_prefix() {
        let true_path = if Path::new("/usr/bin/true").exists() {
            "/usr/bin/true"
        } else {
            "/bin/true"
        };
        let sudo_cmd = format!("{true_path} \"unterminated");
        let env = |k: &str| -> Option<String> {
            if k == "SUDO_COMMAND" {
                Some(sudo_cmd.clone())
            } else {
                None
            }
        };
        let (tool, args) =
            parse_invocation_internal(&argv(&["secure-sudoers", "true", "install"]), env).unwrap();
        assert_eq!(tool, "true");
        assert_eq!(args, argv(&["install"]));
    }

    #[test]
    fn verify_sudo_command_binding_path_identity_mismatch_detected() {
        let dir = tempfile::TempDir::new().unwrap();
        let left_dir = dir.path().join("left");
        let right_dir = dir.path().join("right");
        std::fs::create_dir_all(&left_dir).unwrap();
        std::fs::create_dir_all(&right_dir).unwrap();

        let sudo_tool = left_dir.join("apt");
        let argv_tool = right_dir.join("apt");
        std::fs::write(&sudo_tool, b"left\n").unwrap();
        std::fs::write(&argv_tool, b"right\n").unwrap();
        let mut left_perms = std::fs::metadata(&sudo_tool).unwrap().permissions();
        left_perms.set_mode(0o755);
        std::fs::set_permissions(&sudo_tool, left_perms).unwrap();
        let mut right_perms = std::fs::metadata(&argv_tool).unwrap().permissions();
        right_perms.set_mode(0o755);
        std::fs::set_permissions(&argv_tool, right_perms).unwrap();

        let expected_binary = open_path(sudo_tool.to_str().unwrap());
        let sudo_cmd = format!("{} install", argv_tool.to_string_lossy());
        let env = |k: &str| -> Option<String> {
            if k == "SUDO_COMMAND" {
                Some(sudo_cmd.clone())
            } else {
                None
            }
        };

        let result = verify_sudo_command_binding_internal("apt", &expected_binary, env);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("executable identity mismatch for command")
        );
    }

    #[test]
    fn verify_sudo_command_binding_absolute_path_missing_fails_closed() {
        let dir = tempfile::TempDir::new().unwrap();
        let true_path = if Path::new("/usr/bin/true").exists() {
            "/usr/bin/true"
        } else {
            "/bin/true"
        };
        let expected_binary = open_path(true_path);

        let missing_tool = dir.path().join("true");
        let missing_tool_str = missing_tool.to_string_lossy().to_string();

        let sudo_cmd = format!("{missing_tool_str} install");
        let env = |k: &str| -> Option<String> {
            if k == "SUDO_COMMAND" {
                Some(sudo_cmd.clone())
            } else {
                None
            }
        };

        let result = verify_sudo_command_binding_internal("true", &expected_binary, env);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unable to verify executable identity")
        );
    }

    #[test]
    fn verify_sudo_command_binding_bare_name_match_ok() {
        let true_path = if Path::new("/usr/bin/true").exists() {
            "/usr/bin/true"
        } else {
            "/bin/true"
        };
        let expected_binary = open_path(true_path);
        let env = |k: &str| -> Option<String> {
            if k == "SUDO_COMMAND" {
                Some("true install".to_string())
            } else {
                None
            }
        };

        assert!(verify_sudo_command_binding_internal("true", &expected_binary, env).is_ok());
    }

    #[test]
    fn verify_sudo_command_binding_ignores_malformed_trailing_args() {
        let true_path = if Path::new("/usr/bin/true").exists() {
            "/usr/bin/true"
        } else {
            "/bin/true"
        };
        let expected_binary = open_path(true_path);
        let sudo_cmd = format!("{true_path} install \"unterminated");
        let env = |k: &str| -> Option<String> {
            if k == "SUDO_COMMAND" {
                Some(sudo_cmd.clone())
            } else {
                None
            }
        };

        assert!(verify_sudo_command_binding_internal("true", &expected_binary, env).is_ok());
    }

    #[test]
    fn verify_sudo_command_binding_ignores_malformed_second_token_for_non_wrapper() {
        let true_path = if Path::new("/usr/bin/true").exists() {
            "/usr/bin/true"
        } else {
            "/bin/true"
        };
        let expected_binary = open_path(true_path);
        let sudo_cmd = format!("{true_path} \"unterminated");
        let env = |k: &str| -> Option<String> {
            if k == "SUDO_COMMAND" {
                Some(sudo_cmd.clone())
            } else {
                None
            }
        };

        assert!(verify_sudo_command_binding_internal("true", &expected_binary, env).is_ok());
    }

    #[test]
    fn verify_sudo_command_binding_wrapper_without_subcommand_fails_closed() {
        let true_path = if Path::new("/usr/bin/true").exists() {
            "/usr/bin/true"
        } else {
            "/bin/true"
        };
        let expected_binary = open_path(true_path);
        let env = |k: &str| -> Option<String> {
            if k == "SUDO_COMMAND" {
                Some("/usr/local/bin/secure-sudoers".to_string())
            } else {
                None
            }
        };

        let result = verify_sudo_command_binding_internal("true", &expected_binary, env);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Spoofing attempt detected")
        );
    }

    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use tempfile::TempDir;

    const VALID_POLICY_JSON: &str = r#"{"version":"1.0","global_settings":{},"tools":{}}"#;

    fn generate_keypair() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::generate(&mut OsRng);
        let vk_bytes = sk.verifying_key().to_bytes();
        (sk, vk_bytes)
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

    fn write_policy_and_sig(dir: &TempDir, json: &str, sk: &SigningKey) -> String {
        let policy_path = dir.path().join("policy.json");
        std::fs::write(&policy_path, json).unwrap();
        let sig: Signature = sk.sign(json.as_bytes());
        let sig_path = dir.path().join("policy.json.sig");
        std::fs::write(&sig_path, sig.to_bytes()).unwrap();
        policy_path.to_str().unwrap().to_string()
    }

    #[test]
    fn test_load_policy_missing_file() {
        let dir = TempDir::new().unwrap();
        let missing = dir
            .path()
            .join("nonexistent.json")
            .to_str()
            .unwrap()
            .to_string();
        let result = load_policy_with_pubkey(&missing, "/dev/null");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to read policy"),
            "expected 'Failed to read policy' in error"
        );
    }

    #[test]
    fn test_load_policy_missing_sig() {
        let dir = TempDir::new().unwrap();
        let (sk, vk_bytes) = generate_keypair();
        let pubkey_path = write_pubkey_pem(&dir, &vk_bytes);

        let policy_path = dir.path().join("policy.json");
        std::fs::write(&policy_path, VALID_POLICY_JSON).unwrap();

        let result = load_policy_with_pubkey(policy_path.to_str().unwrap(), &pubkey_path);
        let _ = sk;
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.to_string().contains("missing or unreadable"),
            "expected 'missing or unreadable' in error, got: {msg}"
        );
    }

    #[test]
    fn test_load_policy_invalid_sig_size() {
        let dir = TempDir::new().unwrap();
        let (sk, vk_bytes) = generate_keypair();
        let pubkey_path = write_pubkey_pem(&dir, &vk_bytes);
        let _ = sk;

        let policy_path = dir.path().join("policy.json");
        std::fs::write(&policy_path, VALID_POLICY_JSON).unwrap();
        let bad_sig = vec![0u8; 63];
        std::fs::write(dir.path().join("policy.json.sig"), &bad_sig).unwrap();

        let result = load_policy_with_pubkey(policy_path.to_str().unwrap(), &pubkey_path);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.to_string().contains("signature must be 64 bytes"),
            "expected size error, got: {msg}"
        );
    }

    #[test]
    fn test_load_policy_wrong_key() {
        let dir = TempDir::new().unwrap();
        let (sk_a, _vk_a) = generate_keypair();
        let policy_path = write_policy_and_sig(&dir, VALID_POLICY_JSON, &sk_a);

        let (_sk_b, vk_b_bytes) = generate_keypair();
        let pubkey_b_path = write_pubkey_pem(&dir, &vk_b_bytes);

        let result = load_policy_with_pubkey(&policy_path, &pubkey_b_path);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.to_string().contains("signature verification failed"),
            "expected 'signature verification failed', got: {msg}"
        );
    }

    use crate::require_root;
    use secure_sudoers_common::testing::fixtures::open_path;

    #[test]
    fn test_run_supervisor_true_exits_zero() {
        require_root!();

        use crate::supervisor::run_supervisor;
        use secure_sudoers_common::models::IsolationSettings;
        use secure_sudoers_common::validator::ValidatedCommand;

        let true_bin_str = if Path::new("/usr/bin/true").exists() {
            "/usr/bin/true"
        } else {
            "/bin/true"
        };
        let true_bin = open_path(true_bin_str);

        let cmd = ValidatedCommand::new_for_testing(
            true_bin,
            vec![],
            IsolationSettings {
                unshare_network: false,
                unshare_pid: false,
                unshare_ipc: false,
                unshare_uts: false,
                private_mounts: vec![],
                readonly_mounts: vec![],
            },
            vec![],
        );
        let mut policy = make_policy();
        policy.global_settings.blocked_paths.clear();

        let result = run_supervisor(&cmd, &policy);
        assert_eq!(result.unwrap(), 0, "/usr/bin/true must exit 0");
    }
}
