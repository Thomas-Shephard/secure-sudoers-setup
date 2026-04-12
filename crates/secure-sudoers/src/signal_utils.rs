use secure_sudoers_common::error::Error;

pub(crate) fn is_job_control_stop_signal(sig: nix::sys::signal::Signal) -> bool {
    matches!(
        sig,
        nix::sys::signal::Signal::SIGSTOP
            | nix::sys::signal::Signal::SIGTSTP
            | nix::sys::signal::Signal::SIGTTIN
            | nix::sys::signal::Signal::SIGTTOU
    )
}

pub(crate) fn post_fork_stderr(message: &'static [u8]) {
    let _ = unsafe {
        libc::write(
            libc::STDERR_FILENO,
            message.as_ptr() as *const libc::c_void,
            message.len(),
        )
    };
}

pub(crate) fn fast_exit(code: i32) -> ! {
    unsafe { libc::_exit(code) }
}

pub(crate) fn suspend_self_for_job_control(signal_raw: libc::c_int) -> Result<(), Error> {
    if signal_raw == libc::SIGSTOP {
        if unsafe { libc::raise(signal_raw) } == 0 {
            return Ok(());
        }
        return Err(Error::IoContext(
            format!("failed to propagate stop signal {signal_raw}"),
            std::io::Error::last_os_error(),
        ));
    }

    let mut default_sa: libc::sigaction = unsafe { std::mem::zeroed() };
    default_sa.sa_sigaction = libc::SIG_DFL;
    if unsafe { libc::sigemptyset(&mut default_sa.sa_mask) } != 0 {
        return Err(Error::IoContext(
            "sigemptyset for temporary stop disposition failed".to_string(),
            std::io::Error::last_os_error(),
        ));
    }

    let mut old_sa: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(signal_raw, &default_sa, &mut old_sa) } != 0 {
        return Err(Error::IoContext(
            format!("sigaction({signal_raw}, SIG_DFL) failed"),
            std::io::Error::last_os_error(),
        ));
    }

    if unsafe { libc::raise(signal_raw) } != 0 {
        let _ = unsafe { libc::sigaction(signal_raw, &old_sa, std::ptr::null_mut()) };
        return Err(Error::IoContext(
            format!("failed to propagate stop signal {signal_raw}"),
            std::io::Error::last_os_error(),
        ));
    }

    if unsafe { libc::sigaction(signal_raw, &old_sa, std::ptr::null_mut()) } != 0 {
        return Err(Error::IoContext(
            format!("sigaction({signal_raw}, restore) failed"),
            std::io::Error::last_os_error(),
        ));
    }

    Ok(())
}
