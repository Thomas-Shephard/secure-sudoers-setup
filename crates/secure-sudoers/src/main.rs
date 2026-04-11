#![cfg(target_os = "linux")]

use secure_sudoers::exec::hash_binary_fd;
use secure_sudoers::helpers::binding::verify_sudo_command_binding;
use secure_sudoers::helpers::invocation::parse_invocation_current_process;
use secure_sudoers::helpers::policy::load_policy;
use secure_sudoers::helpers::redaction::redact_args;
use secure_sudoers::supervisor;
use secure_sudoers_common::telemetry::{
    self, AccountType, ContextInfo, IdentityInfo, PolicyInfo, SecurityEvent,
};
use secure_sudoers_common::{logging, validator};
use std::os::fd::AsRawFd;
use tracing::{error, info, warn};

const POLICY_PATH: &str = "/etc/secure-sudoers/policy.json";

fn main() {
    let txn_id = generate_txn_id();

    #[cfg(debug_assertions)]
    let policy_path =
        std::env::var("SECURE_SUDOERS_POLICY_PATH").unwrap_or_else(|_| POLICY_PATH.to_string());
    #[cfg(not(debug_assertions))]
    let policy_path = POLICY_PATH.to_string();

    logging::init_logging_fallback();

    let policy = match load_policy(&policy_path) {
        Ok(p) => p,
        Err(e) => {
            error!(
                txn_id = %txn_id,
                reason = %e,
                "FATAL: policy load failed — possible configuration tampering or DoS"
            );
            eprintln!("FATAL: Cannot load policy: {e}");
            std::process::exit(1);
        }
    };

    logging::init_logging(&policy.global_settings);

    let identity = resolve_identity_triad();

    let (tool_name, raw_args) = match parse_invocation_current_process() {
        Ok(res) => res,
        Err(e) => {
            let ev = SecurityEvent {
                event_id: telemetry::event_id::IDENTITY_SPOOFING.to_string(),
                txn_id: txn_id.clone(),
                timestamp: telemetry::rfc3339_now(),
                identity: identity.clone(),
                context: ContextInfo {
                    tool: String::new(),
                    binary_path: String::new(),
                    binary_hash: String::new(),
                },
                policy: PolicyInfo {
                    status: "error".to_string(),
                    rule_id: None,
                    reason: Some("invocation_error".to_string()),
                },
                args: vec![],
            };
            error!(
                security_event_json = %ev.to_json_or_fallback(),
                "Invocation parse failure"
            );
            eprintln!("FATAL: {e}");
            std::process::exit(1);
        }
    };

    let validation = validator::validate_command(&policy, &tool_name, raw_args.clone());

    match validation {
        Err(denial) => {
            let redacted = redact_args(&raw_args, &policy, &tool_name);
            let ev = SecurityEvent {
                event_id: telemetry::event_id::POLICY_VIOLATION.to_string(),
                txn_id: txn_id.clone(),
                timestamp: telemetry::rfc3339_now(),
                identity: identity.clone(),
                context: ContextInfo {
                    tool: tool_name.clone(),
                    binary_path: String::new(),
                    binary_hash: String::new(),
                },
                policy: PolicyInfo {
                    status: "denied".to_string(),
                    rule_id: denial.rule_id.clone(),
                    reason: Some(denial.reason_slug.clone()),
                },
                args: redacted.iter().map(|s| s.to_string()).collect(),
            };
            warn!(
                security_event_json = %ev.to_json_or_fallback(),
                "Command denied"
            );
            eprintln!("Access denied: {denial}");
            eprintln!("{}", policy.global_settings.admin_contact);
            std::process::exit(1);
        }
        Ok(result) => {
            let cmd = result.command;
            let rule_id = result.rule_id;

            if let Err(e) = verify_sudo_command_binding(&tool_name, cmd.binary()) {
                let ev = SecurityEvent {
                    event_id: telemetry::event_id::IDENTITY_SPOOFING.to_string(),
                    txn_id: txn_id.clone(),
                    timestamp: telemetry::rfc3339_now(),
                    identity: identity.clone(),
                    context: ContextInfo {
                        tool: tool_name.clone(),
                        binary_path: cmd.binary().path.clone(),
                        binary_hash: e
                            .observed_sudo_path()
                            .and_then(hash_path_for_telemetry)
                            .unwrap_or_default(),
                    },
                    policy: PolicyInfo {
                        status: "error".to_string(),
                        rule_id: Some(rule_id.clone()),
                        reason: Some("invocation_error".to_string()),
                    },
                    args: vec![],
                };
                error!(
                    security_event_json = %ev.to_json_or_fallback(),
                    reason = %e,
                    "Invocation spoofing verification failed"
                );
                eprintln!("FATAL: {e}");
                std::process::exit(1);
            }

            let binary_hash = match hash_binary_fd(cmd.binary().fd.as_raw_fd()) {
                Ok(hash) => hash,
                Err(e) => {
                    error!(
                        txn_id = %txn_id,
                        reason = %e,
                        "FATAL: binary hash computation failed — refusing approval"
                    );
                    eprintln!("FATAL: Cannot compute binary hash: {e}");
                    std::process::exit(1);
                }
            };

            let redacted = redact_args(&raw_args, &policy, &tool_name);
            let ev = SecurityEvent {
                event_id: telemetry::event_id::COMMAND_APPROVED.to_string(),
                txn_id: txn_id.clone(),
                timestamp: telemetry::rfc3339_now(),
                identity: identity.clone(),
                context: ContextInfo {
                    tool: tool_name.clone(),
                    binary_path: cmd.binary().path.clone(),
                    binary_hash: binary_hash.clone(),
                },
                policy: PolicyInfo {
                    status: "allowed".to_string(),
                    rule_id: Some(rule_id),
                    reason: None,
                },
                args: redacted.iter().map(|s| s.to_string()).collect(),
            };
            info!(
                security_event_json = %ev.to_json_or_fallback(),
                "Command approved"
            );

            match supervisor::run_supervisor(&cmd, &policy) {
                Ok(exit_code) => std::process::exit(exit_code),
                Err(e) => {
                    let ev_err = SecurityEvent {
                        event_id: telemetry::event_id::EXEC_FAILURE.to_string(),
                        txn_id: txn_id.clone(),
                        timestamp: telemetry::rfc3339_now(),
                        identity,
                        context: ContextInfo {
                            tool: tool_name,
                            binary_path: ev.context.binary_path,
                            binary_hash,
                        },
                        policy: PolicyInfo {
                            status: "error".to_string(),
                            rule_id: ev.policy.rule_id,
                            reason: Some("execution_failure".to_string()),
                        },
                        args: redacted.iter().map(|s| s.to_string()).collect(),
                    };
                    error!(
                        security_event_json = %ev_err.to_json_or_fallback(),
                        "Supervisor failed"
                    );
                    eprintln!("Execution failed: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}

fn generate_txn_id() -> String {
    let mut buf = [0u8; 4];
    if unsafe { libc::getrandom(buf.as_mut_ptr() as *mut libc::c_void, 4, 0) } == 4 {
        format!("{:08x}", u32::from_be_bytes(buf))
    } else {
        // Fallback to XOR pid with current nanoseconds for collision resistance
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("{:08x}", (std::process::id() as u128 ^ nanos) as u32)
    }
}

fn hash_path_for_telemetry(path: &str) -> Option<String> {
    use std::ffi::CString;
    use std::os::fd::{FromRawFd, OwnedFd};

    let c_path = CString::new(path).ok()?;
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return None;
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    hash_binary_fd(fd.as_raw_fd()).ok()
}

fn resolve_identity_triad() -> IdentityInfo {
    use nix::unistd::{Uid, User, geteuid, getuid};
    use std::env;

    let uid = getuid().as_raw();
    let euid = geteuid().as_raw();

    let sudo_uid: Option<u32> = env::var("SUDO_UID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok());

    // Resolve the username from the process real UID.
    let resolved_user = match User::from_uid(Uid::from_raw(uid)) {
        Ok(Some(u)) => Some(u.name),
        Ok(None) => None,
        Err(e) => {
            warn!(uid, error = %e, "failed to resolve username from UID");
            None
        }
    };

    let account_type = resolved_user
        .as_deref()
        .map(|username| classify_account_type(username, uid))
        .unwrap_or(AccountType::Unknown);

    let user = resolved_user.unwrap_or_else(|| format!("uid:{uid}"));

    IdentityInfo {
        user,
        uid,
        euid,
        sudo_uid,
        account_type,
    }
}

fn classify_account_type(username: &str, uid: u32) -> AccountType {
    match classify_account_type_from_etc_passwd(username, uid) {
        Ok(account_type) => account_type,
        Err(e) => {
            warn!(
                uid,
                user = %username,
                error = %e,
                "failed to inspect /etc/passwd for account classification"
            );
            AccountType::Unknown
        }
    }
}

fn classify_account_type_from_etc_passwd(username: &str, uid: u32) -> std::io::Result<AccountType> {
    use std::fs::OpenOptions;
    use std::io::BufReader;
    use std::os::unix::fs::OpenOptionsExt;

    let passwd_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open("/etc/passwd")?;

    classify_account_type_from_reader(username, uid, BufReader::new(passwd_file))
}

fn classify_account_type_from_reader<R: std::io::BufRead>(
    username: &str,
    uid: u32,
    mut reader: R,
) -> std::io::Result<AccountType> {
    let mut line = String::new();
    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line)?;
        if bytes_read == 0 {
            return Ok(AccountType::Network);
        }

        let entry = line.trim_end_matches(['\n', '\r']);
        if entry.is_empty() || entry.starts_with('#') {
            continue;
        }

        if let Some((entry_username, _)) = entry.split_once(':')
            && entry_username == username
        {
            return Ok(if uid < 1000 {
                AccountType::System
            } else {
                AccountType::Local
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const MOCK_PASSWD: &str = "\
root:x:0:0:root:/root:/bin/bash
alice:x:1001:1001:Alice:/home/alice:/bin/bash
";

    #[test]
    fn classify_uid_zero_as_system_for_local_account() {
        let account_type =
            classify_account_type_from_reader("root", 0, Cursor::new(MOCK_PASSWD)).unwrap();
        assert_eq!(account_type, AccountType::System);
    }

    #[test]
    fn classify_uid_over_threshold_as_local_for_local_account() {
        let account_type =
            classify_account_type_from_reader("alice", 1001, Cursor::new(MOCK_PASSWD)).unwrap();
        assert_eq!(account_type, AccountType::Local);
    }

    #[test]
    fn classify_missing_local_account_as_network() {
        let account_type =
            classify_account_type_from_reader("ldap-user", 2001, Cursor::new(MOCK_PASSWD)).unwrap();
        assert_eq!(account_type, AccountType::Network);
    }
}
