use crate::exec;
use crate::signal_utils::{
    fast_exit, is_job_control_stop_signal, post_fork_stderr, suspend_self_for_job_control,
};
use secure_sudoers_common::error::Error;
use secure_sudoers_common::models::SecureSudoersPolicy;
use secure_sudoers_common::validator::ValidatedCommand;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::Duration;
use tracing::{error, warn};

static SIGWINCH_RECEIVED: AtomicBool = AtomicBool::new(false);
static FORWARDED_CHILD_PGID: AtomicI32 = AtomicI32::new(0);
static TERMINATION_SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn sigwinch_handler(_: libc::c_int) {
    SIGWINCH_RECEIVED.store(true, Ordering::SeqCst);
}

extern "C" fn sigint_handler(_: libc::c_int) {
    forward_signal_to_supervised_group(libc::SIGINT);
}

extern "C" fn sigquit_handler(_: libc::c_int) {
    forward_signal_to_supervised_group(libc::SIGQUIT);
}

extern "C" fn sigtstp_handler(_: libc::c_int) {
    forward_signal_to_supervised_group(libc::SIGTSTP);
}

extern "C" fn sigttin_handler(_: libc::c_int) {
    forward_signal_to_supervised_group(libc::SIGTTIN);
}

extern "C" fn sigttou_handler(_: libc::c_int) {
    forward_signal_to_supervised_group(libc::SIGTTOU);
}

extern "C" fn sigterm_handler(_: libc::c_int) {
    TERMINATION_SIGNAL.store(libc::SIGTERM, Ordering::SeqCst);
    forward_signal_to_supervised_group(libc::SIGTERM);
}

extern "C" fn sighup_handler(_: libc::c_int) {
    TERMINATION_SIGNAL.store(libc::SIGHUP, Ordering::SeqCst);
    forward_signal_to_supervised_group(libc::SIGHUP);
}

fn forward_signal_to_supervised_group(signal: libc::c_int) {
    let pgid = FORWARDED_CHILD_PGID.load(Ordering::SeqCst);
    if pgid > 0 {
        unsafe {
            libc::kill(-pgid, signal);
        }
    }
}

const CHILD_STAGE_SET_OWN_PGID: &[u8] = b"set_own_process_group";
const CHILD_STAGE_SET_PDEATHSIG: &[u8] = b"set_parent_death_signal";
const CHILD_STAGE_RESTORE_MASK: &[u8] = b"restore_signal_mask";
const CHILD_STAGE_EXECUTE_SECURELY: &[u8] = b"execute_securely";

fn create_child_error_pipe() -> Result<(OwnedFd, OwnedFd), Error> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return Err(Error::IoContext(
            "pipe2 for supervisor child error channel failed".to_string(),
            std::io::Error::last_os_error(),
        ));
    }

    let read_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((read_fd, write_fd))
}

fn write_child_error_stage(write_fd: &OwnedFd, stage: &'static [u8]) {
    let _ = unsafe {
        libc::write(
            write_fd.as_raw_fd(),
            stage.as_ptr() as *const libc::c_void,
            stage.len(),
        )
    };
}

fn read_child_error_stage(read_fd: &OwnedFd) -> Result<Option<&'static str>, Error> {
    let mut buf = [0u8; 128];
    loop {
        let bytes_read = unsafe {
            libc::read(
                read_fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };

        if bytes_read > 0 {
            let bytes = &buf[..bytes_read as usize];
            if bytes.starts_with(CHILD_STAGE_SET_OWN_PGID) {
                return Ok(Some("set_own_process_group"));
            }
            if bytes.starts_with(CHILD_STAGE_SET_PDEATHSIG) {
                return Ok(Some("set_parent_death_signal"));
            }
            if bytes.starts_with(CHILD_STAGE_RESTORE_MASK) {
                return Ok(Some("restore_signal_mask"));
            }
            if bytes.starts_with(CHILD_STAGE_EXECUTE_SECURELY) {
                return Ok(Some("execute_securely"));
            }
            return Ok(Some("unknown_post_fork_stage"));
        }

        if bytes_read == 0 {
            return Ok(None);
        }

        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EAGAIN) => return Ok(None),
            Some(libc::EINTR) => continue,
            _ => {
                return Err(Error::IoContext(
                    "read supervisor child error channel failed".to_string(),
                    err,
                ));
            }
        }
    }
}

fn block_forwarded_signals() -> Result<libc::sigset_t, Error> {
    let mut set = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    if unsafe { libc::sigemptyset(&mut set) } != 0 {
        return Err(Error::IoContext(
            "sigemptyset for forwarding mask failed".to_string(),
            std::io::Error::last_os_error(),
        ));
    }
    for signal in [
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGTSTP,
        libc::SIGTTIN,
        libc::SIGTTOU,
        libc::SIGTERM,
        libc::SIGHUP,
    ] {
        if unsafe { libc::sigaddset(&mut set, signal) } != 0 {
            return Err(Error::IoContext(
                format!("sigaddset({signal}) failed"),
                std::io::Error::last_os_error(),
            ));
        }
    }

    let mut old_mask = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    let rc = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old_mask) };
    if rc != 0 {
        return Err(Error::IoContext(
            "pthread_sigmask(SIG_BLOCK) failed".to_string(),
            std::io::Error::from_raw_os_error(rc),
        ));
    }
    Ok(old_mask)
}

fn restore_signal_mask(old_mask: &libc::sigset_t) -> Result<(), Error> {
    let rc = unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, old_mask, std::ptr::null_mut()) };
    if rc != 0 {
        return Err(Error::IoContext(
            "pthread_sigmask(SIG_SETMASK) failed".to_string(),
            std::io::Error::from_raw_os_error(rc),
        ));
    }
    Ok(())
}

pub fn run_supervisor(
    cmd: &ValidatedCommand,
    policy: &SecureSudoersPolicy,
    txn_id: &str,
) -> Result<i32, Error> {
    let supervisor_pid = nix::unistd::getpid();
    let stdin_is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) == 1 };
    let mut _tg = None;

    if stdin_is_tty {
        _tg = Some(TerminalGuard::new()?);
        install_sigwinch_handler()?;
    }
    set_subreaper()?;
    FORWARDED_CHILD_PGID.store(0, Ordering::SeqCst);
    TERMINATION_SIGNAL.store(0, Ordering::SeqCst);
    let old_mask = block_forwarded_signals()?;
    let (child_error_read, child_error_write) = match create_child_error_pipe() {
        Ok(fds) => fds,
        Err(e) => {
            let _ = restore_signal_mask(&old_mask);
            return Err(e);
        }
    };

    match unsafe { nix::unistd::fork() } {
        Ok(nix::unistd::ForkResult::Parent { child }) => {
            drop(child_error_write);
            let setup_result = (|| {
                set_child_process_group(child)?;
                FORWARDED_CHILD_PGID.store(child.as_raw(), Ordering::SeqCst);
                install_signal_forwarding_handlers()
            })();
            let restore_result = restore_signal_mask(&old_mask);
            let forwarding_handlers = match setup_result {
                Ok(handlers) => handlers,
                Err(e) => {
                    FORWARDED_CHILD_PGID.store(0, Ordering::SeqCst);
                    let setup_err = if let Err(mask_err) = restore_result {
                        Error::Execution(format!("{e}; restore signal mask failed: {mask_err}"))
                    } else {
                        e
                    };
                    return return_with_setup_child_cleanup(child, setup_err);
                }
            };
            if let Err(e) = restore_result {
                FORWARDED_CHILD_PGID.store(0, Ordering::SeqCst);
                drop(forwarding_handlers);
                return return_with_setup_child_cleanup(child, e);
            }

            let supervise_result = supervise_direct_child(child, stdin_is_tty, txn_id);
            FORWARDED_CHILD_PGID.store(0, Ordering::SeqCst);
            let child_stage = read_child_error_stage(&child_error_read)?;
            drop(forwarding_handlers);

            if let Some(stage) = child_stage {
                let detail = match &supervise_result {
                    Ok(code) => format!("exit code {code}"),
                    Err(e) => format!("supervisor error: {e}"),
                };
                return Err(Error::Execution(format!(
                    "supervisor child failed before delegation at stage '{stage}' ({detail})"
                )));
            }

            supervise_result
        }
        Ok(nix::unistd::ForkResult::Child) => {
            drop(child_error_read);
            if set_parent_death_signal(libc::SIGKILL).is_err() {
                write_child_error_stage(&child_error_write, CHILD_STAGE_SET_PDEATHSIG);
                post_fork_stderr(b"FATAL: set_parent_death_signal failed\n");
                fast_exit(1);
            }
            if nix::unistd::getppid() != supervisor_pid {
                write_child_error_stage(&child_error_write, CHILD_STAGE_SET_PDEATHSIG);
                post_fork_stderr(b"FATAL: supervisor parent changed before delegation startup\n");
                fast_exit(1);
            }
            if set_own_process_group().is_err() {
                write_child_error_stage(&child_error_write, CHILD_STAGE_SET_OWN_PGID);
                post_fork_stderr(b"FATAL: set_own_process_group failed\n");
                fast_exit(1);
            }
            if restore_signal_mask(&old_mask).is_err() {
                write_child_error_stage(&child_error_write, CHILD_STAGE_RESTORE_MASK);
                post_fork_stderr(b"FATAL: restore_signal_mask failed\n");
                fast_exit(1);
            }
            match exec::execute_securely(cmd, policy, Some(child_error_write.as_raw_fd())) {
                Err(_) => fast_exit(1),
                Ok(()) => {
                    // This arm is effectively unreachable: execute_securely's internal
                    // parent exits with the delegated child status.
                    write_child_error_stage(&child_error_write, CHILD_STAGE_EXECUTE_SECURELY);
                    post_fork_stderr(b"FATAL: execute_securely returned unexpectedly\n");
                    fast_exit(1);
                }
            }
        }
        Err(e) => {
            let _ = restore_signal_mask(&old_mask);
            Err(Error::Execution(format!("fork failed: {e}")))
        }
    }
}

fn return_with_setup_child_cleanup(child: nix::unistd::Pid, err: Error) -> Result<i32, Error> {
    if let Err(cleanup_err) = terminate_setup_child(child) {
        return Err(Error::Execution(format!(
            "{err}; setup child cleanup failed: {cleanup_err}"
        )));
    }
    Err(err)
}

fn terminate_setup_child(child: nix::unistd::Pid) -> Result<(), Error> {
    let child_pid = child.as_raw();

    if unsafe { libc::kill(child_pid, libc::SIGKILL) } != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ESRCH) {
            return Err(Error::IoContext(
                format!("kill({child_pid}, SIGKILL) failed during setup cleanup"),
                err,
            ));
        }
    }

    if let Err(e) = send_signal_to_process_group(child_pid, libc::SIGKILL) {
        return Err(Error::Execution(format!(
            "failed to kill setup child process group: {e}"
        )));
    }

    loop {
        match nix::sys::wait::waitpid(child, None) {
            Ok(_) => return Ok(()),
            Err(nix::errno::Errno::EINTR) => continue,
            Err(nix::errno::Errno::ECHILD) => return Ok(()),
            Err(e) => {
                return Err(Error::IoContext(
                    format!("waitpid({child_pid}) failed during setup cleanup"),
                    std::io::Error::from(e),
                ));
            }
        }
    }
}

fn supervise_direct_child(
    child: nix::unistd::Pid,
    stdin_is_tty: bool,
    txn_id: &str,
) -> Result<i32, Error> {
    loop {
        let termination_signal = TERMINATION_SIGNAL.swap(0, Ordering::SeqCst);
        if termination_signal > 0 {
            terminate_supervised_descendants(child)?;
            return Err(Error::Execution(format!(
                "supervisor received termination signal {termination_signal}"
            )));
        }

        if SIGWINCH_RECEIVED.swap(false, Ordering::SeqCst) && stdin_is_tty {
            let child_tty = open_child_stdin_tty(child);
            if let Err(e) = forward_winsize_with_child_tty(child, child_tty.as_ref()) {
                warn!(
                    txn_id = %txn_id,
                    child_pid = child.as_raw(),
                    reason = %e,
                    "Failed to propagate terminal resize to delegated command process group"
                );
            }
        }

        match nix::sys::wait::waitpid(
            child,
            Some(nix::sys::wait::WaitPidFlag::WUNTRACED | nix::sys::wait::WaitPidFlag::WCONTINUED),
        ) {
            Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => {
                terminate_supervised_descendants(child)?;
                return Ok(code);
            }
            Ok(nix::sys::wait::WaitStatus::Signaled(_, sig, _)) => {
                terminate_supervised_descendants(child)?;
                return Ok(128 + sig as i32);
            }
            Ok(nix::sys::wait::WaitStatus::Stopped(_, sig)) => {
                let signal_raw = sig as libc::c_int;
                if !is_job_control_stop_signal(sig) {
                    let err = Error::System(format!(
                        "unexpected non-job-control stop signal: {signal_raw}"
                    ));
                    log_supervisor_failure(txn_id, "wait_supervised", &err);
                    return return_with_descendant_cleanup(child, err);
                }
                warn!(
                    txn_id = %txn_id,
                    child_pid = child.as_raw(),
                    signal = signal_raw,
                    "Supervised child stopped; propagating stop to supervisor"
                );
                if let Err(e) = suspend_self_for_job_control(signal_raw) {
                    return return_with_descendant_cleanup(child, e);
                }
                if let Err(e) = send_signal_to_process_group(child.as_raw(), libc::SIGCONT) {
                    return return_with_descendant_cleanup(child, e);
                }
                continue;
            }
            Ok(nix::sys::wait::WaitStatus::Continued(_)) => continue,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => {
                let mut context = format!("waitpid for child {child} failed");
                if let Err(term_err) = terminate_supervised_descendants(child) {
                    context.push_str(&format!("; cleanup also failed: {term_err}"));
                }
                return Err(Error::IoContext(context, std::io::Error::from(e)));
            }
            Ok(status) => {
                let err = Error::System(format!("Unexpected wait status: {status:?}"));
                log_supervisor_failure(txn_id, "wait_supervised", &err);
                return return_with_descendant_cleanup(child, err);
            }
        }
    }
}

fn return_with_descendant_cleanup(child: nix::unistd::Pid, err: Error) -> Result<i32, Error> {
    if let Err(cleanup_err) = terminate_supervised_descendants(child) {
        return Err(Error::Execution(format!(
            "{err}; cleanup failed: {cleanup_err}"
        )));
    }
    Err(err)
}

fn log_supervisor_failure(txn_id: &str, stage: &'static str, err: &Error) {
    error!(
        txn_id = %txn_id,
        stage,
        reason = %err,
        "Supervisor stage failed"
    );
}

fn set_own_process_group() -> Result<(), Error> {
    match nix::unistd::setpgid(nix::unistd::Pid::from_raw(0), nix::unistd::Pid::from_raw(0)) {
        Ok(()) => Ok(()),
        Err(e) => Err(Error::IoContext(
            "setpgid(0, 0) failed".to_string(),
            std::io::Error::from(e),
        )),
    }
}

fn set_child_process_group(child: nix::unistd::Pid) -> Result<(), Error> {
    match nix::unistd::setpgid(child, child) {
        Ok(()) => Ok(()),
        Err(nix::errno::Errno::ESRCH) | Err(nix::errno::Errno::EACCES) => Ok(()),
        Err(e) => Err(Error::IoContext(
            format!("setpgid({child}, {child}) failed"),
            std::io::Error::from(e),
        )),
    }
}

fn set_parent_death_signal(sig: libc::c_int) -> Result<(), Error> {
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, sig, 0, 0, 0) } != 0 {
        return Err(Error::IoContext(
            format!("prctl(PR_SET_PDEATHSIG, {sig}) failed"),
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn set_subreaper() -> Result<(), Error> {
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
        return Err(Error::IoContext(
            "prctl(PR_SET_CHILD_SUBREAPER) failed".to_string(),
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn send_signal_to_process_group(pgid: libc::pid_t, signal: libc::c_int) -> Result<(), Error> {
    if pgid <= 0 {
        return Ok(());
    }
    if unsafe { libc::kill(-pgid, signal) } == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(Error::Execution(format!(
            "kill(-{pgid}, {signal}) failed: {err}"
        )))
    }
}

fn send_signal_to_pid(pid: libc::pid_t, signal: libc::c_int) -> Result<(), Error> {
    if unsafe { libc::kill(pid, signal) } == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(Error::Execution(format!(
            "kill({pid}, {signal}) failed: {err}"
        )))
    }
}

fn parse_ppid_from_stat(stat: &str) -> Option<libc::pid_t> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    if close <= open {
        return None;
    }
    let after_comm = stat.get(close + 1..)?.trim_start();
    let mut fields = after_comm.split_whitespace();
    let _state = fields.next()?;
    fields.next()?.parse::<libc::pid_t>().ok()
}

fn process_group_exists(pgid: libc::pid_t) -> bool {
    if pgid <= 0 {
        return false;
    }
    unsafe {
        libc::kill(-pgid, 0) == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
}

fn list_direct_children(ppid: libc::pid_t) -> Result<Vec<libc::pid_t>, Error> {
    let mut children = Vec::new();
    let proc_entries = std::fs::read_dir("/proc")
        .map_err(|e| Error::IoContext("read_dir('/proc') failed".to_string(), e))?;

    for entry in proc_entries {
        let Ok(entry) = entry else {
            continue;
        };
        let file_name = entry.file_name();
        let Some(pid) = file_name
            .to_str()
            .and_then(|name| name.parse::<libc::pid_t>().ok())
        else {
            continue;
        };

        let stat_path = format!("/proc/{pid}/stat");
        let Ok(stat) = std::fs::read_to_string(&stat_path) else {
            continue;
        };

        if parse_ppid_from_stat(&stat) == Some(ppid) {
            children.push(pid);
        }
    }

    Ok(children)
}

fn reap_all_children_nonblocking() {
    loop {
        match nix::sys::wait::waitpid(
            nix::unistd::Pid::from_raw(-1),
            Some(nix::sys::wait::WaitPidFlag::WNOHANG),
        ) {
            Ok(nix::sys::wait::WaitStatus::StillAlive) => break,
            Ok(_) => continue,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(nix::errno::Errno::ECHILD) => break,
            Err(_) => break,
        }
    }
}

fn terminate_adopted_descendants() -> Result<(), Error> {
    let supervisor_pid = unsafe { libc::getpid() };

    for (signal, rounds) in [(libc::SIGTERM, 10), (libc::SIGKILL, 10)] {
        for _ in 0..rounds {
            reap_all_children_nonblocking();
            let children = list_direct_children(supervisor_pid)?;
            if children.is_empty() {
                return Ok(());
            }
            for pid in children {
                send_signal_to_pid(pid, signal)?;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    reap_all_children_nonblocking();
    let remaining = list_direct_children(supervisor_pid)?;
    if remaining.is_empty() {
        Ok(())
    } else {
        Err(Error::System(format!(
            "failed to terminate descendant processes: {remaining:?}"
        )))
    }
}

fn terminate_supervised_descendants(child: nix::unistd::Pid) -> Result<(), Error> {
    let child_pgid = child.as_raw();
    send_signal_to_process_group(child_pgid, libc::SIGTERM)?;
    if process_group_exists(child_pgid) {
        std::thread::sleep(Duration::from_millis(50));
        send_signal_to_process_group(child_pgid, libc::SIGKILL)?;
    }
    terminate_adopted_descendants()
}

struct TerminalGuard {
    original_termios: libc::termios,
}

impl TerminalGuard {
    fn new() -> Result<Self, Error> {
        let mut termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut termios) } != 0 {
            return Err(Error::IoContext(
                "tcgetattr failed".to_string(),
                std::io::Error::last_os_error(),
            ));
        }
        let guard = Self {
            original_termios: termios,
        };

        let mut raw = termios;
        unsafe { libc::cfmakeraw(&mut raw) };
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSADRAIN, &raw) } != 0 {
            return Err(Error::IoContext(
                "tcsetattr failed".to_string(),
                std::io::Error::last_os_error(),
            ));
        }

        Ok(guard)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSADRAIN, &self.original_termios);
        }
    }
}

fn install_sigwinch_handler() -> Result<(), Error> {
    install_signal_handler(libc::SIGWINCH, sigwinch_handler).map(|_| ())
}

struct ForwardingSignalHandlerGuard {
    installed: Vec<(libc::c_int, libc::sigaction)>,
}

impl ForwardingSignalHandlerGuard {
    fn new() -> Self {
        Self {
            installed: Vec::new(),
        }
    }

    fn install(
        &mut self,
        signal: libc::c_int,
        handler: extern "C" fn(libc::c_int),
    ) -> Result<(), Error> {
        let old = install_signal_handler(signal, handler)?;
        self.installed.push((signal, old));
        Ok(())
    }
}

impl Drop for ForwardingSignalHandlerGuard {
    fn drop(&mut self) {
        for (signal, old_action) in self.installed.iter().rev() {
            unsafe {
                libc::sigaction(*signal, old_action, std::ptr::null_mut());
            }
        }
    }
}

fn install_signal_forwarding_handlers() -> Result<ForwardingSignalHandlerGuard, Error> {
    let mut guard = ForwardingSignalHandlerGuard::new();
    guard.install(libc::SIGINT, sigint_handler)?;
    guard.install(libc::SIGQUIT, sigquit_handler)?;
    guard.install(libc::SIGTSTP, sigtstp_handler)?;
    guard.install(libc::SIGTTIN, sigttin_handler)?;
    guard.install(libc::SIGTTOU, sigttou_handler)?;
    guard.install(libc::SIGTERM, sigterm_handler)?;
    guard.install(libc::SIGHUP, sighup_handler)?;
    Ok(guard)
}

fn install_signal_handler(
    signal: libc::c_int,
    handler: extern "C" fn(libc::c_int),
) -> Result<libc::sigaction, Error> {
    let mut sa = libc::sigaction {
        sa_sigaction: handler as *const () as usize,
        sa_mask: unsafe { std::mem::zeroed() },
        sa_flags: 0,
        sa_restorer: None,
    };
    if unsafe { libc::sigemptyset(&mut sa.sa_mask) } != 0 {
        return Err(Error::IoContext(
            "sigemptyset failed".to_string(),
            std::io::Error::last_os_error(),
        ));
    }
    let mut old_sa: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(signal, &sa, &mut old_sa) } != 0 {
        return Err(Error::IoContext(
            format!("sigaction({signal}) failed"),
            std::io::Error::last_os_error(),
        ));
    }
    Ok(old_sa)
}

struct ChildTtyForwarding {
    fd: std::fs::File,
    needs_winsize_sync: bool,
}

fn stat_identity(fd: libc::c_int) -> Option<(libc::dev_t, libc::ino_t)> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return None;
    }
    Some((st.st_dev, st.st_ino))
}

fn open_child_stdin_tty(child: nix::unistd::Pid) -> Option<ChildTtyForwarding> {
    use std::os::fd::AsRawFd;

    let fd = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(format!("/proc/{}/fd/0", child.as_raw()))
        .ok()?;

    let parent_id = stat_identity(libc::STDIN_FILENO);
    let child_id = stat_identity(fd.as_raw_fd());
    let needs_winsize_sync = match (parent_id, child_id) {
        (Some(p), Some(c)) => p != c,
        _ => true,
    };

    Some(ChildTtyForwarding {
        fd,
        needs_winsize_sync,
    })
}

fn forward_winsize_with_child_tty(
    child: nix::unistd::Pid,
    child_tty: Option<&ChildTtyForwarding>,
) -> Result<(), Error> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) } != 0 {
        return Ok(());
    }

    let Some(child_tty) = child_tty else {
        return send_signal_to_process_group(child.as_raw(), libc::SIGWINCH);
    };

    if child_tty.needs_winsize_sync {
        use std::os::fd::AsRawFd;
        let mut child_ws: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(child_tty.fd.as_raw_fd(), libc::TIOCGWINSZ, &mut child_ws) } == 0
            && (child_ws.ws_row != ws.ws_row
                || child_ws.ws_col != ws.ws_col
                || child_ws.ws_xpixel != ws.ws_xpixel
                || child_ws.ws_ypixel != ws.ws_ypixel)
        {
            // Successful TIOCSWINSZ typically triggers kernel SIGWINCH delivery for the tty.
            if unsafe { libc::ioctl(child_tty.fd.as_raw_fd(), libc::TIOCSWINSZ, &ws) } == 0 {
                return Ok(());
            }
        }
    }

    send_signal_to_process_group(child.as_raw(), libc::SIGWINCH)
}

pub fn run_simple_supervisor(child: nix::unistd::Pid) -> Result<i32, Error> {
    match nix::sys::wait::waitpid(child, None) {
        Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => Ok(code),
        Ok(nix::sys::wait::WaitStatus::Signaled(_, sig, _)) => Ok(128 + sig as i32),
        _ => Ok(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::require_root;
    use crate::testing::in_fork;
    use secure_sudoers_common::models::IsolationSettings;
    use secure_sudoers_common::testing::fixtures::{make_policy, open_path};
    use secure_sudoers_common::validator::ValidatedCommand;
    use std::sync::Mutex;

    static SUPERVISOR_TEST_LOCK: Mutex<()> = Mutex::new(());
    extern "C" fn noop_sigwinch_handler(_: libc::c_int) {}

    #[test]
    fn test_sigwinch_handler_sets_flag() {
        let _guard = SUPERVISOR_TEST_LOCK.lock().expect("lock poisoned");
        use std::sync::atomic::Ordering;
        SIGWINCH_RECEIVED.store(false, Ordering::SeqCst);
        sigwinch_handler(libc::SIGWINCH);
        assert!(SIGWINCH_RECEIVED.load(Ordering::SeqCst));
        SIGWINCH_RECEIVED.store(false, Ordering::SeqCst);
    }

    #[test]
    fn test_parse_ppid_from_stat_parses_expected_field() {
        let _guard = SUPERVISOR_TEST_LOCK.lock().expect("lock poisoned");
        let sample = "12345 (my proc) S 678 100 100 0 -1 4194560 10 0 0 0 0 0 0 0 20 0 1 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1";
        assert_eq!(parse_ppid_from_stat(sample), Some(678));
    }

    #[test]
    fn test_supervisor_tty_stdin_covers_raw_mode_and_winch() {
        let _guard = SUPERVISOR_TEST_LOCK.lock().expect("lock poisoned");
        require_root!();

        fn child_fn() -> bool {
            use std::sync::atomic::Ordering;
            let mut master_raw: libc::c_int = -1;
            let mut slave_raw: libc::c_int = -1;
            let ret = unsafe {
                libc::openpty(
                    &mut master_raw,
                    &mut slave_raw,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if ret != 0 {
                eprintln!("  openpty failed");
                return false;
            }

            if unsafe { libc::dup2(slave_raw, libc::STDIN_FILENO) } < 0 {
                eprintln!("  dup2 failed");
                return false;
            }
            unsafe { libc::close(slave_raw) };

            SIGWINCH_RECEIVED.store(true, Ordering::Relaxed);

            let policy = make_policy();
            let true_bin_str = if std::path::Path::new("/usr/bin/true").exists() {
                "/usr/bin/true"
            } else {
                "/bin/true"
            };
            let true_bin = open_path(true_bin_str);

            let cmd = ValidatedCommand::new_for_testing(
                true_bin,
                vec![],
                IsolationSettings::default(),
                vec![],
            );
            match run_supervisor(&cmd, &policy, "test-txn-id") {
                Ok(0) => true,
                Ok(c) => {
                    eprintln!("  exit code {c}");
                    false
                }
                Err(e) => {
                    eprintln!("  err: {e}");
                    false
                }
            }
        }

        assert!(unsafe { in_fork(child_fn) });
    }

    #[test]
    fn test_forward_winsize_reaches_child_process_group() {
        let _guard = SUPERVISOR_TEST_LOCK.lock().expect("lock poisoned");
        fn read_one_byte(fd: libc::c_int) -> Option<u8> {
            let mut b = [0u8; 1];
            loop {
                let n = unsafe { libc::read(fd, b.as_mut_ptr() as *mut libc::c_void, 1) };
                if n == 1 {
                    return Some(b[0]);
                }
                if n == 0 {
                    return None;
                }
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return None;
            }
        }

        fn child_fn() -> bool {
            use nix::sys::wait::waitpid;
            use nix::unistd::{ForkResult, Pid, fork, setpgid};

            let mut master_raw: libc::c_int = -1;
            let mut slave_raw: libc::c_int = -1;
            let ret = unsafe {
                libc::openpty(
                    &mut master_raw,
                    &mut slave_raw,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if ret != 0 {
                return false;
            }
            if unsafe { libc::dup2(slave_raw, libc::STDIN_FILENO) } < 0 {
                return false;
            }
            unsafe {
                libc::close(slave_raw);
            }

            let mut fds = [0; 2];
            if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
                return false;
            }
            let read_fd = fds[0];
            let write_fd = fds[1];

            match unsafe { fork() } {
                Ok(ForkResult::Child) => {
                    unsafe { libc::close(read_fd) };
                    let _ = setpgid(Pid::from_raw(0), Pid::from_raw(0));

                    match unsafe { fork() } {
                        Ok(ForkResult::Child) => {
                            let sa = libc::sigaction {
                                sa_sigaction: noop_sigwinch_handler as *const () as usize,
                                sa_mask: unsafe { std::mem::zeroed() },
                                sa_flags: 0,
                                sa_restorer: None,
                            };
                            let _ = unsafe {
                                libc::sigaction(libc::SIGWINCH, &sa, std::ptr::null_mut())
                            };

                            let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
                            unsafe {
                                libc::sigemptyset(&mut set);
                                libc::sigaddset(&mut set, libc::SIGWINCH);
                                libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
                            }

                            let ready = [1u8; 1];
                            let _ = unsafe {
                                libc::write(
                                    write_fd,
                                    ready.as_ptr() as *const libc::c_void,
                                    ready.len(),
                                )
                            };

                            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                            let timeout = libc::timespec {
                                tv_sec: 2,
                                tv_nsec: 0,
                            };
                            let rc = unsafe { libc::sigtimedwait(&set, &mut info, &timeout) };
                            let marker = if rc == libc::SIGWINCH {
                                [1u8; 1]
                            } else {
                                [0u8; 1]
                            };
                            let _ = unsafe {
                                libc::write(
                                    write_fd,
                                    marker.as_ptr() as *const libc::c_void,
                                    marker.len(),
                                )
                            };
                            unsafe { libc::close(write_fd) };
                            std::process::exit(0);
                        }
                        Ok(ForkResult::Parent { .. }) => {
                            unsafe { libc::close(write_fd) };
                            std::process::exit(0);
                        }
                        Err(_) => std::process::exit(2),
                    }
                }
                Ok(ForkResult::Parent { child }) => {
                    let _ = setpgid(child, child);
                    unsafe { libc::close(write_fd) };

                    if waitpid(child, None).is_err() {
                        unsafe { libc::close(read_fd) };
                        unsafe { libc::close(master_raw) };
                        return false;
                    }

                    if read_one_byte(read_fd) != Some(1) {
                        unsafe { libc::close(read_fd) };
                        unsafe { libc::close(master_raw) };
                        return false;
                    }

                    let child_tty_fd = open_child_stdin_tty(child);
                    if forward_winsize_with_child_tty(child, child_tty_fd.as_ref()).is_err() {
                        unsafe { libc::close(read_fd) };
                        unsafe { libc::close(master_raw) };
                        return false;
                    }

                    let got_winch = read_one_byte(read_fd) == Some(1);
                    unsafe {
                        libc::close(read_fd);
                        libc::close(master_raw);
                    };
                    got_winch
                }
                Err(_) => {
                    unsafe {
                        libc::close(read_fd);
                        libc::close(write_fd);
                        libc::close(master_raw);
                    }
                    false
                }
            }
        }

        assert!(unsafe { in_fork(child_fn) });
    }

    #[test]
    fn test_supervisor_terminates_daemonized_descendant() {
        let _guard = SUPERVISOR_TEST_LOCK.lock().expect("lock poisoned");
        use nix::unistd::{ForkResult, Pid, fork, setpgid};
        set_subreaper().expect("set_subreaper failed");

        let mut fds = [0; 2];
        let pipe_rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(pipe_rc, 0, "pipe failed");
        let read_fd = fds[0];
        let write_fd = fds[1];

        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                unsafe { libc::close(read_fd) };
                let _ = setpgid(Pid::from_raw(0), Pid::from_raw(0));

                match unsafe { fork() } {
                    Ok(ForkResult::Child) => {
                        let _ = unsafe { libc::setsid() };
                        let daemon_pid = unsafe { libc::getpid() };
                        let pid_bytes = daemon_pid.to_ne_bytes();
                        let _ = unsafe {
                            libc::write(
                                write_fd,
                                pid_bytes.as_ptr() as *const libc::c_void,
                                pid_bytes.len(),
                            )
                        };
                        unsafe { libc::close(write_fd) };
                        loop {
                            std::thread::sleep(std::time::Duration::from_secs(1));
                        }
                    }
                    Ok(ForkResult::Parent { .. }) => std::process::exit(0),
                    Err(_) => std::process::exit(2),
                }
            }
            Ok(ForkResult::Parent { child }) => {
                unsafe { libc::close(write_fd) };
                let mut buf = [0u8; std::mem::size_of::<libc::pid_t>()];
                let mut off = 0usize;
                while off < buf.len() {
                    let n = unsafe {
                        libc::read(
                            read_fd,
                            buf[off..].as_mut_ptr() as *mut libc::c_void,
                            (buf.len() - off) as libc::size_t,
                        )
                    };
                    if n <= 0 {
                        break;
                    }
                    off += n as usize;
                }
                unsafe { libc::close(read_fd) };
                assert_eq!(off, buf.len(), "failed to read daemon pid");
                let daemon_pid = i32::from_ne_bytes(buf);

                let exit_code =
                    supervise_direct_child(child, false, "test-txn-id").expect("supervise failed");
                assert_eq!(exit_code, 0);

                std::thread::sleep(std::time::Duration::from_millis(100));
                let daemon_alive = unsafe { libc::kill(daemon_pid, 0) == 0 };

                if daemon_alive {
                    unsafe {
                        libc::kill(daemon_pid, libc::SIGKILL);
                    }
                }

                assert!(
                    !daemon_alive,
                    "daemonized descendant escaped supervision and remained alive"
                );
            }
            Err(e) => panic!("fork failed: {e}"),
        }
    }

    #[test]
    fn test_forward_winsize_propagates_terminal_size_to_child_tty() {
        let _guard = SUPERVISOR_TEST_LOCK.lock().expect("lock poisoned");
        fn read_one_byte(fd: libc::c_int) -> Option<u8> {
            let mut b = [0u8; 1];
            loop {
                let n = unsafe { libc::read(fd, b.as_mut_ptr() as *mut libc::c_void, 1) };
                if n == 1 {
                    return Some(b[0]);
                }
                if n == 0 {
                    return None;
                }
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return None;
            }
        }

        fn child_fn() -> bool {
            use nix::unistd::{ForkResult, Pid, fork, setpgid};
            use std::sync::atomic::Ordering;

            // Isolate this forked test process in its own process group so
            // group-targeted cleanup cannot accidentally hit the test harness.
            let _ = setpgid(Pid::from_raw(0), Pid::from_raw(0));

            let mut source_master: libc::c_int = -1;
            let mut source_slave: libc::c_int = -1;
            let ret = unsafe {
                libc::openpty(
                    &mut source_master,
                    &mut source_slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if ret != 0 {
                return false;
            }

            let mut target_master: libc::c_int = -1;
            let mut target_slave: libc::c_int = -1;
            let ret = unsafe {
                libc::openpty(
                    &mut target_master,
                    &mut target_slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if ret != 0 {
                unsafe {
                    libc::close(source_master);
                    libc::close(source_slave);
                }
                return false;
            }

            if unsafe { libc::dup2(source_slave, libc::STDIN_FILENO) } < 0 {
                unsafe {
                    libc::close(source_master);
                    libc::close(source_slave);
                    libc::close(target_master);
                    libc::close(target_slave);
                }
                return false;
            }
            unsafe { libc::close(source_slave) };

            let initial_target_ws = libc::winsize {
                ws_row: 9,
                ws_col: 21,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            if unsafe { libc::ioctl(target_master, libc::TIOCSWINSZ, &initial_target_ws) } != 0 {
                unsafe {
                    libc::close(source_master);
                    libc::close(target_master);
                    libc::close(target_slave);
                }
                return false;
            }

            let mut child_to_parent = [0; 2];
            if unsafe { libc::pipe(child_to_parent.as_mut_ptr()) } != 0 {
                unsafe {
                    libc::close(source_master);
                    libc::close(target_master);
                    libc::close(target_slave);
                }
                return false;
            }

            match unsafe { fork() } {
                Ok(ForkResult::Child) => {
                    let _ = setpgid(Pid::from_raw(0), Pid::from_raw(0));
                    unsafe {
                        libc::close(child_to_parent[0]);
                        libc::close(source_master);
                        libc::close(target_master);
                    }
                    if unsafe { libc::dup2(target_slave, libc::STDIN_FILENO) } < 0 {
                        std::process::exit(2);
                    }
                    unsafe { libc::close(target_slave) };

                    let ready = [1u8; 1];
                    let ready_write = unsafe {
                        libc::write(
                            child_to_parent[1],
                            ready.as_ptr() as *const libc::c_void,
                            ready.len(),
                        )
                    };
                    if ready_write != 1 {
                        std::process::exit(2);
                    }

                    let mut ok = false;
                    for _ in 0..200 {
                        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
                        if unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) }
                            == 0
                            && ws.ws_row == 55
                            && ws.ws_col == 101
                        {
                            ok = true;
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }

                    let marker = if ok { [1u8; 1] } else { [0u8; 1] };
                    let _ = unsafe {
                        libc::write(
                            child_to_parent[1],
                            marker.as_ptr() as *const libc::c_void,
                            marker.len(),
                        )
                    };
                    unsafe {
                        libc::close(child_to_parent[1]);
                    }
                    std::process::exit(0);
                }
                Ok(ForkResult::Parent { child }) => {
                    let _ = setpgid(child, child);
                    unsafe {
                        libc::close(target_slave);
                        libc::close(child_to_parent[1]);
                    }

                    if read_one_byte(child_to_parent[0]) != Some(1) {
                        unsafe {
                            libc::close(source_master);
                            libc::close(target_master);
                            libc::close(child_to_parent[0]);
                        }
                        return false;
                    }

                    let desired = libc::winsize {
                        ws_row: 55,
                        ws_col: 101,
                        ws_xpixel: 0,
                        ws_ypixel: 0,
                    };
                    if unsafe { libc::ioctl(source_master, libc::TIOCSWINSZ, &desired) } != 0 {
                        unsafe {
                            libc::close(source_master);
                            libc::close(target_master);
                            libc::close(child_to_parent[0]);
                        }
                        return false;
                    }

                    SIGWINCH_RECEIVED.store(true, Ordering::SeqCst);
                    let exit_code = supervise_direct_child(child, true, "test-txn-id").ok();
                    if exit_code != Some(0) {
                        unsafe {
                            libc::close(source_master);
                            libc::close(target_master);
                            libc::close(child_to_parent[0]);
                        }
                        return false;
                    }

                    let got = read_one_byte(child_to_parent[0]) == Some(1);

                    unsafe {
                        libc::close(source_master);
                        libc::close(target_master);
                        libc::close(child_to_parent[0]);
                    }
                    got
                }
                Err(_) => {
                    unsafe {
                        libc::close(source_master);
                        libc::close(target_master);
                        libc::close(target_slave);
                        libc::close(child_to_parent[0]);
                        libc::close(child_to_parent[1]);
                    }
                    false
                }
            }
        }

        assert!(unsafe { in_fork(child_fn) });
    }
}
