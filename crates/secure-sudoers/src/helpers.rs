use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use secure_sudoers_common::error::Error;
use secure_sudoers_common::models::{
    ParameterConfig, ParameterType, SecurePath, SecureSudoersPolicy,
};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::path::Path;
use tracing::{error, info, warn};

const PUBLIC_KEY_PATH: &str = "/etc/secure-sudoers/secure_sudoers_public_key.pem";

pub fn parse_invocation(raw_argv: &[String]) -> Result<(String, Vec<String>), Error> {
    parse_invocation_internal(raw_argv, |v| std::env::var(v).ok())
}

pub fn parse_invocation_current_process() -> Result<(String, Vec<String>), Error> {
    let raw_argv = match read_proc_self_cmdline() {
        Ok(argv) => argv,
        Err(e) => {
            info!(
                reason = %e,
                "Unable to read /proc/self/cmdline; falling back to std::env::args"
            );
            std::env::args().collect()
        }
    };
    parse_invocation_internal(&raw_argv, |v| std::env::var(v).ok())
}

fn read_proc_self_cmdline() -> Result<Vec<String>, Error> {
    let bytes = std::fs::read("/proc/self/cmdline")
        .map_err(|e| Error::IoContext("Cannot read /proc/self/cmdline".to_string(), e))?;
    parse_proc_self_cmdline_bytes(&bytes)
}

fn parse_proc_self_cmdline_bytes(bytes: &[u8]) -> Result<Vec<String>, Error> {
    let mut chunks: Vec<&[u8]> = bytes.split(|b| *b == 0).collect();
    if chunks.last().is_some_and(|chunk| chunk.is_empty()) {
        chunks.pop();
    }
    if chunks.is_empty() {
        return Err(Error::Validation(
            "Cannot parse /proc/self/cmdline: missing argv tokens".to_string(),
        ));
    }

    let mut argv = Vec::new();
    for chunk in chunks {
        let token = std::str::from_utf8(chunk).map_err(|_| {
            Error::Validation("Cannot parse /proc/self/cmdline: non-UTF8 argv token".to_string())
        })?;
        argv.push(token.to_string());
    }

    Ok(argv)
}

fn parse_invocation_internal<F>(
    raw_argv: &[String],
    get_env: F,
) -> Result<(String, Vec<String>), Error>
where
    F: Fn(&str) -> Option<String>,
{
    if raw_argv.is_empty() {
        return Ok((String::new(), vec![]));
    }

    let (argv_tool_token, argv_tool_name, args) = {
        let exe_path = Path::new(&raw_argv[0]);
        let exe_name = exe_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if exe_name == "secure-sudoers" || exe_name == "secure_sudoers" {
            if raw_argv.len() < 2 {
                (String::new(), String::new(), vec![])
            } else {
                (
                    raw_argv[1].clone(),
                    basename(&raw_argv[1]).to_string(),
                    raw_argv[2..].to_vec(),
                )
            }
        } else {
            (
                raw_argv[0].clone(),
                exe_name.to_string(),
                raw_argv[1..].to_vec(),
            )
        }
    };

    match get_env("SUDO_COMMAND") {
        Some(sudo_cmd) => {
            let sudo_tool_token = match delegated_command_token_from_sudo_command(&sudo_cmd) {
                Ok(token) => token,
                Err(SudoCommandTokenError::InvalidPrefix) => {
                    return Err(Error::Spoofing(
                        "Spoofing attempt detected: invalid SUDO_COMMAND command prefix"
                            .to_string(),
                    ));
                }
                Err(SudoCommandTokenError::MissingDelegatedCommand) => {
                    error!(
                        argv0 = %raw_argv[0],
                        sudo_command = %sudo_cmd,
                        "CRITICAL: Spoofing attempt detected! SUDO_COMMAND missing delegated command."
                    );
                    return Err(Error::Spoofing(
                        "Spoofing attempt detected: SUDO_COMMAND is missing delegated command token"
                            .to_string(),
                    ));
                }
            };

            if sudo_tool_token.is_empty() {
                error!(
                    argv0 = %raw_argv[0],
                    sudo_command = %sudo_cmd,
                    "CRITICAL: Spoofing attempt detected! SUDO_COMMAND missing delegated command."
                );
                return Err(Error::Spoofing(
                    "Spoofing attempt detected: SUDO_COMMAND is missing delegated command token"
                        .to_string(),
                ));
            }

            let argv_tool_basename = basename(&argv_tool_token);
            let sudo_tool_basename = basename(&sudo_tool_token);

            if sudo_tool_basename != argv_tool_basename {
                error!(
                    argv0 = %raw_argv[0],
                    sudo_tool = %sudo_tool_basename,
                    argv_tool = %argv_tool_basename,
                    "CRITICAL: Spoofing attempt detected! Invocation mismatch with SUDO_COMMAND."
                );
                return Err(Error::Spoofing(format!(
                    "Spoofing attempt detected: command '{}' does not match SUDO_COMMAND '{}'",
                    argv_tool_basename, sudo_tool_basename
                )));
            }

            Ok((sudo_tool_basename.to_string(), args))
        }
        None => {
            warn!("Tool is running outside of a secure Sudo context (SUDO_COMMAND missing)");
            Ok((argv_tool_name, args))
        }
    }
}

fn basename(token: &str) -> &str {
    Path::new(token)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(token)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SudoCommandTokenError {
    InvalidPrefix,
    MissingDelegatedCommand,
}

fn delegated_command_token_from_sudo_command(
    sudo_cmd: &str,
) -> Result<String, SudoCommandTokenError> {
    let first_tokens = split_sudo_command_prefix_tokens(sudo_cmd, 1)
        .ok_or(SudoCommandTokenError::InvalidPrefix)?;
    let first_token = first_tokens.first().map(String::as_str).unwrap_or("");
    let first_name = basename(first_token);

    if (first_name == "secure-sudoers" || first_name == "secure_sudoers") && !first_token.is_empty()
    {
        let tokens = split_sudo_command_prefix_tokens(sudo_cmd, 2)
            .ok_or(SudoCommandTokenError::InvalidPrefix)?;
        tokens
            .get(1)
            .cloned()
            .ok_or(SudoCommandTokenError::MissingDelegatedCommand)
    } else {
        Ok(first_token.to_string())
    }
}

fn split_sudo_command_prefix_tokens(s: &str, max_tokens: usize) -> Option<Vec<String>> {
    if max_tokens == 0 {
        return Some(Vec::new());
    }

    let mut chars = s.chars().peekable();
    let mut tokens = Vec::new();
    while tokens.len() < max_tokens {
        while matches!(chars.peek(), Some(ch) if ch.is_whitespace()) {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }

        let mut token = String::new();
        let mut quote: Option<char> = None;
        let mut escaped = false;

        for ch in chars.by_ref() {
            if escaped {
                token.push(ch);
                escaped = false;
                continue;
            }

            if ch == '\\' && quote != Some('\'') {
                escaped = true;
                continue;
            }

            if let Some(q) = quote {
                if ch == q {
                    quote = None;
                } else {
                    token.push(ch);
                }
                continue;
            }

            if ch == '\'' || ch == '"' {
                quote = Some(ch);
                continue;
            }

            if ch.is_whitespace() {
                break;
            }

            token.push(ch);
        }

        if escaped || quote.is_some() {
            return None;
        }

        tokens.push(token);
    }

    Some(tokens)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecutableIdentity {
    dev: u64,
    ino: u64,
}

#[derive(Debug, Clone)]
pub struct SudoBindingError {
    message: String,
    observed_sudo_path: Option<String>,
}

impl SudoBindingError {
    fn new(message: impl Into<String>, observed_sudo_path: Option<String>) -> Self {
        Self {
            message: message.into(),
            observed_sudo_path,
        }
    }

    pub fn observed_sudo_path(&self) -> Option<&str> {
        self.observed_sudo_path.as_deref()
    }
}

impl std::fmt::Display for SudoBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SudoBindingError {}

pub fn verify_sudo_command_binding(
    tool_name: &str,
    expected_binary: &SecurePath,
) -> Result<(), SudoBindingError> {
    verify_sudo_command_binding_internal(tool_name, expected_binary, |v| std::env::var(v).ok())
}

fn verify_sudo_command_binding_internal<F>(
    tool_name: &str,
    expected_binary: &SecurePath,
    get_env: F,
) -> Result<(), SudoBindingError>
where
    F: Fn(&str) -> Option<String>,
{
    let Some(sudo_cmd) = get_env("SUDO_COMMAND") else {
        return Ok(());
    };

    let sudo_tool_token = match delegated_command_token_from_sudo_command(&sudo_cmd) {
        Ok(token) => token,
        Err(SudoCommandTokenError::InvalidPrefix) => {
            return Err(SudoBindingError::new(
                "Spoofing attempt detected: invalid SUDO_COMMAND command prefix",
                None,
            ));
        }
        Err(SudoCommandTokenError::MissingDelegatedCommand) => {
            error!(
                expected_tool = %tool_name,
                sudo_command = %sudo_cmd,
                "CRITICAL: Spoofing attempt detected! SUDO_COMMAND missing delegated command."
            );
            return Err(SudoBindingError::new(
                "Spoofing attempt detected: SUDO_COMMAND is missing delegated command token",
                None,
            ));
        }
    };

    if sudo_tool_token.is_empty() {
        error!(
            expected_tool = %tool_name,
            sudo_command = %sudo_cmd,
            "CRITICAL: Spoofing attempt detected! SUDO_COMMAND missing delegated command."
        );
        return Err(SudoBindingError::new(
            "Spoofing attempt detected: SUDO_COMMAND is missing delegated command token",
            None,
        ));
    }

    let expected_tool_basename = basename(tool_name);
    let sudo_tool_basename = basename(&sudo_tool_token);
    if sudo_tool_basename != expected_tool_basename {
        error!(
            expected_tool = %expected_tool_basename,
            sudo_tool = %sudo_tool_basename,
            "CRITICAL: Spoofing attempt detected! Invocation mismatch with SUDO_COMMAND."
        );
        return Err(SudoBindingError::new(
            format!(
                "Spoofing attempt detected: command '{}' does not match SUDO_COMMAND '{}'",
                expected_tool_basename, sudo_tool_basename
            ),
            if sudo_tool_token.contains('/') {
                Some(sudo_tool_token.clone())
            } else {
                None
            },
        ));
    }

    if !sudo_tool_token.contains('/') {
        return Ok(());
    }

    let sudo_identity = executable_identity_from_path(&sudo_tool_token).map_err(|e| {
        let failure_kind = match &e {
            Error::IoContext(_, io_err) if io_err.kind() == ErrorKind::NotFound => "not_found",
            Error::IoContext(_, io_err) if io_err.kind() == ErrorKind::PermissionDenied => {
                "permission_denied"
            }
            _ => "io_error",
        };
        error!(
            sudo_tool = %sudo_tool_token,
            failure_kind,
            reason = %e,
            "CRITICAL: Spoofing attempt detected! Unable to verify SUDO_COMMAND executable identity."
        );
        SudoBindingError::new(
            "Spoofing attempt detected: unable to verify executable identity",
            Some(sudo_tool_token.clone()),
        )
    })?;
    let expected_identity =
        executable_identity_from_fd(expected_binary.fd.as_raw_fd()).map_err(|e| {
            error!(
                expected_path = %expected_binary.path,
                reason = %e,
                "CRITICAL: Spoofing attempt detected! Unable to verify validated executable identity."
            );
            SudoBindingError::new(
                "Spoofing attempt detected: unable to verify executable identity",
                Some(expected_binary.path.clone()),
            )
        })?;

    if sudo_identity != expected_identity {
        error!(
            expected_tool = %expected_tool_basename,
            expected_path = %expected_binary.path,
            sudo_tool = %sudo_tool_token,
            "CRITICAL: Spoofing attempt detected! Executable identity mismatch."
        );
        return Err(SudoBindingError::new(
            format!(
                "Spoofing attempt detected: executable identity mismatch for command '{}'",
                expected_tool_basename
            ),
            Some(sudo_tool_token.clone()),
        ));
    }

    Ok(())
}

fn executable_identity_from_path(path: &str) -> Result<ExecutableIdentity, Error> {
    use std::ffi::CString;
    use std::os::fd::{FromRawFd, OwnedFd};

    let c_path = CString::new(path).map_err(|_| {
        Error::Validation(format!(
            "cannot open executable path '{}': invalid NUL byte",
            path
        ))
    })?;
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(Error::IoContext(
            format!("cannot open executable path '{}'", path),
            std::io::Error::last_os_error(),
        ));
    }

    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    executable_identity_from_fd(fd.as_raw_fd())
        .map_err(|e| Error::System(format!("cannot stat executable path '{}': {}", path, e)))
}

fn executable_identity_from_fd(fd: i32) -> Result<ExecutableIdentity, Error> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, st.as_mut_ptr()) } != 0 {
        return Err(Error::IoContext(
            "fstat failed".to_string(),
            std::io::Error::last_os_error(),
        ));
    }
    let st = unsafe { st.assume_init() };

    Ok(ExecutableIdentity {
        dev: st.st_dev,
        ino: st.st_ino,
    })
}

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

fn is_known_flag_argument(arg: &str, parameters: &HashMap<String, ParameterConfig>) -> bool {
    if arg.starts_with("--") {
        if let Some(idx) = arg.find('=') {
            return parameters.contains_key(&arg[..idx]);
        }
        return parameters.contains_key(arg);
    }

    if !arg.starts_with('-') || arg == "-" {
        return false;
    }

    if parameters.contains_key(arg) {
        return true;
    }

    for c in arg[1..].chars() {
        let short_flag = format!("-{c}");
        let Some(config) = parameters.get(&short_flag) else {
            return false;
        };

        if config.param_type != ParameterType::Bool {
            return true;
        }
    }

    true
}

pub fn redact_args(args: &[String], policy: &SecureSudoersPolicy, tool_name: &str) -> Vec<String> {
    if let Some(tool) = policy.tools.get(tool_name) {
        let mut redacted = Vec::with_capacity(args.len());
        let mut skip_next = false;
        let mut after_double_dash = false;
        for arg in args {
            if skip_next {
                redacted.push("[REDACTED]".to_string());
                skip_next = false;
                continue;
            }

            if arg == "--" {
                redacted.push(arg.clone());
                after_double_dash = true;
                continue;
            }

            if after_double_dash
                && let Some(ref pos_config) = tool.positional
                && pos_config.sensitive
            {
                redacted.push("[REDACTED]".to_string());
                continue;
            }

            if let Some(idx) = arg.find('=') {
                let key = &arg[..idx];
                if let Some(config) = tool.parameters.get(key)
                    && config.sensitive
                {
                    redacted.push(format!("{}=[REDACTED]", key));
                    continue;
                }
            }

            let mut attached_found = false;
            for (f_name, config) in &tool.parameters {
                if config.sensitive
                    && f_name.starts_with('-')
                    && !f_name.starts_with("--")
                    && f_name.len() == 2
                {
                    let flag_char = f_name.chars().nth(1).unwrap();
                    if arg.starts_with('-')
                        && !arg.starts_with("--")
                        && let Some(pos) = arg.find(flag_char)
                    {
                        if pos < arg.len() - 1 {
                            redacted.push(format!("{}[REDACTED]", &arg[..pos + 1]));
                        } else {
                            redacted.push(arg.clone());
                            skip_next = true;
                        }
                        attached_found = true;
                        break;
                    }
                }
            }
            if attached_found {
                continue;
            }

            if let Some(config) = tool.parameters.get(arg)
                && config.sensitive
            {
                redacted.push(arg.clone());
                skip_next = true;
            } else if !after_double_dash && arg.starts_with("--") {
                if let Some(idx) = arg.find('=') {
                    let key = &arg[..idx];
                    if !tool.parameters.contains_key(key) {
                        redacted.push(format!("{key}=[REDACTED]"));
                        continue;
                    }
                } else if !tool.parameters.contains_key(arg) {
                    redacted.push(arg.clone());
                    skip_next = true;
                    continue;
                }
            } else if let Some(ref pos_config) = tool.positional
                && pos_config.sensitive
            {
                if arg.starts_with('-') && is_known_flag_argument(arg, &tool.parameters) {
                    redacted.push(arg.clone());
                } else {
                    redacted.push("[REDACTED]".to_string());
                }
            } else {
                redacted.push(arg.clone());
            }
        }
        redacted
    } else {
        use secure_sudoers_common::models::UnauthorizedAuditMode;
        match policy.global_settings.unauthorized_audit_mode {
            UnauthorizedAuditMode::Minimal => {
                vec![format!("[{} arguments suppressed]", args.len())]
            }
            UnauthorizedAuditMode::KeysOnly => args
                .iter()
                .map(|arg| {
                    if let Some(idx) = arg.find('=') {
                        let key = &arg[..idx];
                        if key.starts_with('-') {
                            return format!("{}=[REDACTED]", key);
                        }
                    } else if arg.starts_with('-') {
                        if !arg.starts_with("--") && arg.len() > 2 {
                            return format!("{}[REDACTED]", &arg[..2]);
                        }
                        return arg.clone();
                    }
                    "[REDACTED]".to_string()
                })
                .collect(),
            UnauthorizedAuditMode::Full => args.to_vec(),
        }
    }
}

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
