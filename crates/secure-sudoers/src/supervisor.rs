use crate::exec;
use secure_sudoers_common::error::Error;
use secure_sudoers_common::models::SecureSudoersPolicy;
use secure_sudoers_common::validator::ValidatedCommand;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static SIGWINCH_RECEIVED: AtomicBool = AtomicBool::new(false);

extern "C" fn sigwinch_handler(_: libc::c_int) {
    SIGWINCH_RECEIVED.store(true, Ordering::SeqCst);
}

pub fn run_supervisor(cmd: &ValidatedCommand, policy: &SecureSudoersPolicy) -> Result<i32, Error> {
    let stdin_is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) == 1 };
    let mut _tg = None;

    if stdin_is_tty {
        _tg = Some(TerminalGuard::new()?);
        install_sigwinch_handler()?;
    }
    set_subreaper()?;

    match unsafe { nix::unistd::fork() } {
        Ok(nix::unistd::ForkResult::Parent { child }) => {
            unsafe {
                libc::signal(libc::SIGINT, libc::SIG_IGN);
                libc::signal(libc::SIGQUIT, libc::SIG_IGN);
            }
            set_child_process_group(child)?;
            supervise_direct_child(child, stdin_is_tty)
        }
        Ok(nix::unistd::ForkResult::Child) => {
            set_own_process_group()?;
            set_parent_death_signal(libc::SIGKILL)?;
            if let Err(e) = exec::execute_securely(cmd, policy) {
                eprintln!("FATAL: {e}");
                std::process::exit(1);
            }
            std::process::exit(0);
        }
        Err(e) => Err(Error::Execution(format!("fork failed: {e}"))),
    }
}

fn supervise_direct_child(child: nix::unistd::Pid, stdin_is_tty: bool) -> Result<i32, Error> {
    loop {
        if SIGWINCH_RECEIVED.swap(false, Ordering::SeqCst) && stdin_is_tty {
            let child_tty = open_child_stdin_tty(child);
            let _ = forward_winsize_with_child_tty(child, child_tty.as_ref());
        }

        match nix::sys::wait::waitpid(child, None) {
            Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => {
                terminate_supervised_descendants(child)?;
                return Ok(code);
            }
            Ok(nix::sys::wait::WaitStatus::Signaled(_, sig, _)) => {
                terminate_supervised_descendants(child)?;
                return Ok(128 + sig as i32);
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => {
                let _ = terminate_supervised_descendants(child);
                return Err(Error::IoContext(
                    format!("waitpid for child {child} failed"),
                    std::io::Error::from(e),
                ));
            }
            _ => continue,
        }
    }
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
    let sa = libc::sigaction {
        sa_sigaction: sigwinch_handler as *const () as usize,
        sa_mask: unsafe { std::mem::zeroed() },
        sa_flags: 0,
        sa_restorer: None,
    };
    if unsafe { libc::sigaction(libc::SIGWINCH, &sa, std::ptr::null_mut()) } != 0 {
        return Err(Error::IoContext(
            "sigaction failed".to_string(),
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
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
            match run_supervisor(&cmd, &policy) {
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

                let exit_code = supervise_direct_child(child, false).expect("supervise failed");
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
                    let exit_code = supervise_direct_child(child, true).ok();
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
