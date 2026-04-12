use crate::signal_utils::{
    fast_exit, is_job_control_stop_signal, post_fork_stderr, suspend_self_for_job_control,
};
use nix::unistd::fexecve;
use secure_sudoers_common::error::Error;
use secure_sudoers_common::models::SecureSudoersPolicy;
use secure_sudoers_common::validator::ValidatedCommand;
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::io::Read;
use std::os::fd::FromRawFd;
use std::path::Path;

pub fn hash_binary_fd(fd_raw: std::os::unix::io::RawFd) -> Result<String, Error> {
    let proc_path = format!("/proc/self/fd/{}", fd_raw);
    let file = std::fs::File::open(&proc_path).map_err(|e| {
        Error::IoContext(format!("Cannot open binary for hashing via {proc_path}"), e)
    })?;
    let mut reader = std::io::BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| Error::IoContext("Read error while hashing binary".to_string(), e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:064x}", hasher.finalize()))
}

pub fn execute_securely(
    cmd: &ValidatedCommand,
    policy: &SecureSudoersPolicy,
    error_stage_fd: Option<libc::c_int>,
) -> Result<(), Error> {
    use std::os::fd::AsRawFd;

    // Use the already opened FD from the validation phase to prevent TOCTOU
    let binary_fd_raw =
        unsafe { libc::fcntl(cmd.binary().fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if binary_fd_raw < 0 {
        let err = Error::IoContext(
            "failed to duplicate binary file descriptor".to_string(),
            std::io::Error::last_os_error(),
        );
        mark_exec_failure(error_stage_fd);
        return Err(err);
    }
    let binary_file = unsafe { std::fs::File::from_raw_fd(binary_fd_raw) };

    let clean_env = build_scrubbed_env(cmd.env_whitelist());

    crate::isolation::setup_isolation(cmd.isolation(), &policy.global_settings.blocked_paths)
        .inspect_err(|_e| {
            mark_exec_failure(error_stage_fd);
        })?;

    crate::isolation::capabilities::drop_capabilities().inspect_err(|_e| {
        mark_exec_failure(error_stage_fd);
    })?;

    let binary_name = Path::new(&cmd.binary().path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&cmd.binary().path);
    let mut argv: Vec<CString> = Vec::with_capacity(1 + cmd.args().len());
    argv.push(CString::new(binary_name).map_err(|e| {
        let err = Error::System(format!("Binary name contains NUL byte: {e}"));
        mark_exec_failure(error_stage_fd);
        err
    })?);
    for (arg_index, arg) in cmd.args().iter().enumerate() {
        let arg_str = arg.as_str();
        argv.push(CString::new(arg_str).map_err(|e| {
            let err = Error::System(format!(
                "Command argument index {arg_index} contains NUL byte: {e}"
            ));
            mark_exec_failure(error_stage_fd);
            err
        })?);
    }

    let envp: Result<Vec<CString>, Error> = clean_env
        .iter()
        .map(|(k, v)| {
            CString::new(format!("{k}={v}")).map_err(|e| {
                let err = Error::System(format!("Env var '{k}' contains NUL byte: {e}"));
                mark_exec_failure(error_stage_fd);
                err
            })
        })
        .collect();
    let envp = envp?;

    // Keep this post-isolation fork: when CLONE_NEWPID is requested via unshare(),
    // the calling process stays in the parent PID namespace and only children join
    // the new one. Spawning the delegated command here is what makes PID isolation
    // effective while still allowing the supervisor to observe a stable child exit.
    let wrapper_pid = nix::unistd::getpid();
    match unsafe { nix::unistd::fork() } {
        Ok(nix::unistd::ForkResult::Parent { child }) => {
            unsafe {
                libc::signal(libc::SIGINT, libc::SIG_IGN);
                libc::signal(libc::SIGQUIT, libc::SIG_IGN);
            }
            loop {
                match nix::sys::wait::waitpid(
                    child,
                    Some(
                        nix::sys::wait::WaitPidFlag::WUNTRACED
                            | nix::sys::wait::WaitPidFlag::WCONTINUED,
                    ),
                ) {
                    Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => fast_exit(code),
                    Ok(nix::sys::wait::WaitStatus::Signaled(_, sig, _)) => {
                        fast_exit(128 + sig as i32)
                    }
                    Ok(nix::sys::wait::WaitStatus::Stopped(_, sig)) => {
                        let signal_raw = sig as libc::c_int;
                        if !is_job_control_stop_signal(sig) {
                            mark_exec_failure(error_stage_fd);
                            post_fork_stderr(
                                b"FATAL: unexpected non-job-control stop signal in wrapper\n",
                            );
                            fast_exit(1);
                        }
                        if suspend_self_for_job_control(signal_raw).is_err() {
                            mark_exec_failure(error_stage_fd);
                            post_fork_stderr(b"FATAL: failed to propagate stop signal\n");
                            fast_exit(1);
                        }
                        if send_sigcont_to_current_group().is_err() {
                            mark_exec_failure(error_stage_fd);
                            post_fork_stderr(
                                b"FATAL: failed to propagate SIGCONT to delegated process group\n",
                            );
                            fast_exit(1);
                        }
                        continue;
                    }
                    Ok(nix::sys::wait::WaitStatus::Continued(_)) => continue,
                    Err(nix::errno::Errno::EINTR) => continue,
                    Ok(_status) => {
                        mark_exec_failure(error_stage_fd);
                        post_fork_stderr(b"FATAL: unexpected wait status in delegated wrapper\n");
                        fast_exit(1);
                    }
                    Err(_e) => {
                        mark_exec_failure(error_stage_fd);
                        post_fork_stderr(b"FATAL: waitpid failed for delegated child\n");
                        fast_exit(1);
                    }
                }
            }
        }
        Ok(nix::unistd::ForkResult::Child) => {
            if let Err(err) = set_exec_parent_death_signal(wrapper_pid) {
                mark_exec_failure(error_stage_fd);
                return Err(err);
            }
            if let Err(err) = reset_exec_signal_defaults() {
                mark_exec_failure(error_stage_fd);
                return Err(err);
            }
            match fexecve(&binary_file, &argv, &envp) {
                Ok(infallible) => match infallible {},
                Err(e) => {
                    let err =
                        Error::IoContext("fexecve failed".to_string(), std::io::Error::from(e));
                    mark_exec_failure(error_stage_fd);
                    Err(err)
                }
            }
        }
        Err(e) => {
            let err = Error::IoContext("fork failed".to_string(), std::io::Error::from(e));
            mark_exec_failure(error_stage_fd);
            Err(err)
        }
    }
}

const EXEC_STAGE_FAILURE: &[u8] = b"execute_securely";

fn mark_exec_failure(error_stage_fd: Option<libc::c_int>) {
    if let Some(fd) = error_stage_fd {
        let mut written = 0usize;
        while written < EXEC_STAGE_FAILURE.len() {
            let remaining = &EXEC_STAGE_FAILURE[written..];
            let result = unsafe {
                libc::write(
                    fd,
                    remaining.as_ptr() as *const libc::c_void,
                    remaining.len(),
                )
            };
            if result > 0 {
                written += result as usize;
                continue;
            }
            if result == 0 {
                break;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
    }
}

fn set_exec_parent_death_signal(expected_parent: nix::unistd::Pid) -> Result<(), Error> {
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        return Err(Error::IoContext(
            "prctl(PR_SET_PDEATHSIG, SIGKILL) failed".to_string(),
            std::io::Error::last_os_error(),
        ));
    }
    if nix::unistd::getppid() != expected_parent {
        return Err(Error::Execution(
            "delegated exec wrapper parent changed before fexecve".to_string(),
        ));
    }
    Ok(())
}

fn reset_exec_signal_defaults() -> Result<(), Error> {
    // Ensure the delegated command does not inherit supervisor/wrapper signal
    // dispositions for interactive control and termination signals.
    for signal in [
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGPIPE,
        libc::SIGTERM,
        libc::SIGHUP,
        libc::SIGTSTP,
        libc::SIGTTIN,
        libc::SIGTTOU,
        libc::SIGWINCH,
    ] {
        let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
        sa.sa_sigaction = libc::SIG_DFL;
        if unsafe { libc::sigemptyset(&mut sa.sa_mask) } != 0 {
            return Err(Error::IoContext(
                format!("sigemptyset for signal {signal} failed"),
                std::io::Error::last_os_error(),
            ));
        }
        if unsafe { libc::sigaction(signal, &sa, std::ptr::null_mut()) } != 0 {
            return Err(Error::IoContext(
                format!("sigaction({signal}, SIG_DFL) failed"),
                std::io::Error::last_os_error(),
            ));
        }
    }
    Ok(())
}

fn send_sigcont_to_current_group() -> Result<(), Error> {
    let pgid = unsafe { libc::getpgrp() };
    if pgid <= 0 {
        return Err(Error::System(format!(
            "invalid current process group id while propagating SIGCONT: {pgid}"
        )));
    }

    if unsafe { libc::kill(-pgid, libc::SIGCONT) } == 0 {
        return Ok(());
    }

    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(Error::IoContext(
            format!("kill(-{pgid}, SIGCONT) failed"),
            err,
        ))
    }
}

pub fn build_scrubbed_env(whitelist: &[String]) -> Vec<(String, String)> {
    std::env::vars()
        .filter(|(key, _)| whitelist.contains(key))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    fn wl(keys: &[&str]) -> Vec<String> {
        keys.iter().map(|s| s.to_string()).collect()
    }
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        keys: Vec<String>,
    }

    impl EnvGuard {
        fn new(pairs: &[(&str, &str)]) -> Self {
            let guard = ENV_LOCK.lock().unwrap();
            let mut keys = Vec::new();
            for (k, v) in pairs {
                unsafe {
                    std::env::set_var(k, v);
                }
                keys.push(k.to_string());
            }
            Self { _lock: guard, keys }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for k in &self.keys {
                unsafe {
                    std::env::remove_var(k);
                }
            }
        }
    }

    #[test]
    fn test_whitelisted_var_is_kept() {
        let _g = EnvGuard::new(&[("TERM", "xterm")]);
        let env = build_scrubbed_env(&wl(&["TERM"]));
        assert!(env.iter().any(|(k, _)| k == "TERM"));
    }

    #[test]
    fn test_ld_preload_is_stripped() {
        let _g = EnvGuard::new(&[("LD_PRELOAD", "evil.so"), ("TERM", "xterm")]);
        let env = build_scrubbed_env(&wl(&["TERM"]));
        assert!(!env.iter().any(|(k, _)| k == "LD_PRELOAD"));
    }
}
