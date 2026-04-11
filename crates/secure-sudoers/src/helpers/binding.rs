use super::sudo_command::{
    SudoCommandTokenError, basename, delegated_command_token_from_sudo_command,
};
use secure_sudoers_common::error::Error;
use secure_sudoers_common::models::SecurePath;
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use tracing::error;

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

pub(super) fn verify_sudo_command_binding_internal<F>(
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
