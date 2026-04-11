use super::sudo_command::{
    SudoCommandTokenError, basename, delegated_command_token_from_sudo_command,
};
use secure_sudoers_common::error::Error;
use std::path::Path;
use tracing::{error, info, warn};

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

pub(super) fn parse_proc_self_cmdline_bytes(bytes: &[u8]) -> Result<Vec<String>, Error> {
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

pub(super) fn parse_invocation_internal<F>(
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
