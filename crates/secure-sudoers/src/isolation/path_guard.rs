use secure_sudoers_common::error::Error;
use std::io::Error as IoError;
use std::os::fd::AsRawFd;

pub(super) fn proc_fd_path(fd: i32) -> String {
    format!("/proc/self/fd/{fd}")
}

pub(super) fn fstat_for_fd(fd: i32, context_path: &str) -> Result<libc::stat, Error> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(Error::IoContext(
            format!("fstat failed on '{}'", context_path),
            IoError::last_os_error(),
        ));
    }
    Ok(st)
}

pub(super) fn ensure_path_matches_fd(path_str: &str, expected_fd: i32) -> Result<(), Error> {
    ensure_path_matches_fd_with_stat(path_str, expected_fd).map(|_| ())
}

pub(super) fn ensure_path_matches_fd_with_stat(
    path_str: &str,
    expected_fd: i32,
) -> Result<libc::stat, Error> {
    // Intentionally re-traverse here to catch path swaps that may occur
    // after the caller captured expected_fd but before the sensitive use.
    let current_fd = safe_traverse(path_str, false)?;
    let expected = fstat_for_fd(expected_fd, path_str)?;
    let current = fstat_for_fd(current_fd.as_raw_fd(), path_str)?;

    if expected.st_dev != current.st_dev || expected.st_ino != current.st_ino {
        return Err(Error::Security(format!(
            "Security failure: path '{}' does not match the expected file descriptor",
            path_str
        )));
    }
    Ok(expected)
}

pub(super) fn safe_traverse(path_str: &str, create: bool) -> Result<std::os::fd::OwnedFd, Error> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let path = std::path::Path::new(path_str);
    if !path.is_absolute() {
        return Err(Error::Security(format!(
            "Security failure: path '{}' is not absolute",
            path_str
        )));
    }

    let root_c =
        std::ffi::CString::new("/").map_err(|_| Error::System("Nul byte in root path".into()))?;
    let root_raw = unsafe {
        libc::open(
            root_c.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if root_raw < 0 {
        return Err(Error::IoContext(
            "Security failure: cannot open root".to_string(),
            IoError::last_os_error(),
        ));
    }
    let mut current_fd: OwnedFd = unsafe { OwnedFd::from_raw_fd(root_raw) };

    let components: Vec<_> = path
        .components()
        .filter(|component| !matches!(component, std::path::Component::RootDir))
        .collect();
    for (i, comp) in components.iter().enumerate() {
        let comp_str = comp
            .as_os_str()
            .to_str()
            .ok_or_else(|| Error::Validation("Invalid path component".to_string()))?;
        let c_comp = std::ffi::CString::new(comp_str)
            .map_err(|_| Error::Validation("Nul byte in path component".to_string()))?;
        let is_last = i == components.len() - 1;

        let next_raw = unsafe {
            libc::openat(
                current_fd.as_raw_fd(),
                c_comp.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };

        if next_raw >= 0 {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(next_raw, &mut st) } != 0 {
                let err = IoError::last_os_error();
                unsafe { libc::close(next_raw) };
                return Err(Error::IoContext(
                    format!(
                        "Security failure: fstat failed on component '{}' of '{}'",
                        comp_str, path_str
                    ),
                    err,
                ));
            }

            if (st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
                unsafe { libc::close(next_raw) };
                return Err(Error::Security(format!(
                    "Security failure: symlink detected during traversal of '{}' at '{}'",
                    path_str, comp_str
                )));
            }

            current_fd = unsafe { OwnedFd::from_raw_fd(next_raw) };
        } else {
            let err = IoError::last_os_error();
            if err.raw_os_error() == Some(libc::ELOOP) {
                return Err(Error::Security(format!(
                    "Security failure: symlink detected during traversal of '{}' at '{}'",
                    path_str, comp_str
                )));
            }

            if err.kind() != std::io::ErrorKind::NotFound || !create {
                return Err(Error::IoContext(
                    format!(
                        "Security failure: error traversing '{}' at '{}'",
                        path_str, comp_str
                    ),
                    err,
                ));
            }

            if is_last && !path_str.ends_with('/') {
                let fd = unsafe {
                    libc::openat(
                        current_fd.as_raw_fd(),
                        c_comp.as_ptr(),
                        libc::O_WRONLY
                            | libc::O_CREAT
                            | libc::O_EXCL
                            | libc::O_NOFOLLOW
                            | libc::O_CLOEXEC,
                        0o000u32,
                    )
                };
                if fd < 0 {
                    let e2 = IoError::last_os_error();
                    if e2.kind() != std::io::ErrorKind::AlreadyExists {
                        return Err(Error::IoContext(
                            format!("Security failure: cannot create mask file '{}'", path_str),
                            e2,
                        ));
                    }
                } else {
                    unsafe { libc::close(fd) };
                }
            } else {
                let ret = unsafe { libc::mkdirat(current_fd.as_raw_fd(), c_comp.as_ptr(), 0o000) };
                if ret != 0 {
                    let e2 = IoError::last_os_error();
                    if e2.kind() != std::io::ErrorKind::AlreadyExists {
                        return Err(Error::IoContext(
                            format!("Security failure: cannot create mask dir '{}'", path_str),
                            e2,
                        ));
                    }
                }
            }

            let next_raw2 = unsafe {
                libc::openat(
                    current_fd.as_raw_fd(),
                    c_comp.as_ptr(),
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if next_raw2 < 0 {
                return Err(Error::IoContext(
                    format!(
                        "Security failure: cannot open component '{}' of '{}' after creation",
                        comp_str, path_str
                    ),
                    IoError::last_os_error(),
                ));
            }
            current_fd = unsafe { OwnedFd::from_raw_fd(next_raw2) };
        }
    }
    Ok(current_fd)
}
