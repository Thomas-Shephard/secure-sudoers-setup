use secure_sudoers_common::error::Error;
use secure_sudoers_common::fs::check_path;
use secure_sudoers_common::models::{SecurePath, ValidationContext};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

pub(crate) fn secure_directory(path: &Path, label: &str) -> Result<SecurePath, Error> {
    let path_str = path.to_str().ok_or_else(|| {
        Error::System(format!(
            "Cannot validate {label}: path is not valid UTF-8 ({})",
            path.display()
        ))
    })?;
    let secure_dir = check_path(path_str, &ValidationContext::Positional, &[])?;
    ensure_directory_is_hardened(&secure_dir, label)?;
    Ok(secure_dir)
}

pub(crate) fn secure_parent_directory(target: &Path, label: &str) -> Result<SecurePath, Error> {
    let parent = target.parent().ok_or_else(|| {
        Error::System(format!(
            "Cannot validate {label}: missing parent directory for {}",
            target.display()
        ))
    })?;
    secure_directory(parent, label)
}

pub(crate) fn proc_fd_directory_path(secure_dir: &SecurePath) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", secure_dir.fd.as_raw_fd()))
}

fn ensure_directory_is_hardened(secure_dir: &SecurePath, label: &str) -> Result<(), Error> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(secure_dir.fd.as_raw_fd(), &mut stat) };
    if rc != 0 {
        return Err(Error::IoContext(
            format!("Cannot inspect {label} {} with fstat", secure_dir.path),
            std::io::Error::last_os_error(),
        ));
    }

    if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(Error::Security(format!(
            "Security violation: {label} {} is not a directory",
            secure_dir.path
        )));
    }

    if unsafe { libc::geteuid() } == 0 {
        if stat.st_uid != 0 {
            return Err(Error::Security(format!(
                "Security violation: {label} {} must be owned by root (uid 0), found uid {}",
                secure_dir.path, stat.st_uid
            )));
        }

        let mode = stat.st_mode & 0o777;
        if (mode & 0o022) != 0 {
            return Err(Error::Security(format!(
                "Security violation: {label} {} must not be writable by group/others (mode {:03o})",
                secure_dir.path, mode
            )));
        }
    }

    Ok(())
}
