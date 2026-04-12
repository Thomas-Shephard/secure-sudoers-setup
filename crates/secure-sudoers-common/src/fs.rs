use crate::error::Error;
use crate::models::{SecurePath, ValidationContext};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Component, Path, PathBuf};

const MAX_SYMLINK_DEPTH: u32 = 32;

pub fn check_path(
    arg: &str,
    _context: &ValidationContext,
    blocked_paths: &[String],
) -> Result<SecurePath, Error> {
    let path = Path::new(arg);
    if !path.is_absolute() {
        return Err(Error::Security(format!(
            "Security failure: path must be absolute: {}",
            arg
        )));
    }

    let mut symlink_count = 0;
    resolve_securely(path, blocked_paths, &mut symlink_count)
}

fn resolve_securely(
    path: &Path,
    blocked_paths: &[String],
    symlink_count: &mut u32,
) -> Result<SecurePath, Error> {
    let mut current_fd = open_root()?;
    let mut current_canonical = PathBuf::from("/");

    let components: Vec<_> = path.components().skip(1).collect();

    for (i, comp) in components.iter().enumerate() {
        let (comp_str, is_normal) = match comp {
            Component::Normal(s) => (
                s.to_str()
                    .ok_or_else(|| Error::Validation("Invalid path component".to_string()))?,
                true,
            ),
            Component::ParentDir => ("..", false),
            Component::CurDir => continue,
            _ => continue,
        };
        let c_comp = std::ffi::CString::new(comp_str)
            .map_err(|_| Error::System("Nul byte in component".into()))?;

        let fd_raw = unsafe {
            libc::openat(
                current_fd.as_raw_fd(),
                c_comp.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };

        if fd_raw >= 0 {
            if is_normal {
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(fd_raw, &mut st) } == 0
                    && (st.st_mode & libc::S_IFMT) == libc::S_IFLNK
                {
                    let symlink_fd = unsafe { OwnedFd::from_raw_fd(fd_raw) };

                    *symlink_count += 1;
                    if *symlink_count > MAX_SYMLINK_DEPTH {
                        return Err(Error::Security(
                            "Security failure: too many symlinks".to_string(),
                        ));
                    }

                    let link_target = read_link_from_fd(symlink_fd.as_raw_fd())?;
                    let link_path = Path::new(&link_target);

                    let mut new_path = if link_path.is_absolute() {
                        link_path.to_path_buf()
                    } else {
                        current_canonical.join(link_path)
                    };

                    for rem in &components[i + 1..] {
                        new_path.push(rem);
                    }
                    return resolve_securely(&new_path, blocked_paths, symlink_count);
                }
                current_canonical.push(comp_str);
            } else {
                current_canonical.pop();
            }

            current_fd = unsafe { OwnedFd::from_raw_fd(fd_raw) };
            check_blocked(&current_canonical.to_string_lossy(), blocked_paths)?;
        } else {
            return Err(Error::IoContext(
                format!(
                    "Security failure: cannot open component '{}' of '{}'",
                    comp_str,
                    path.display()
                ),
                std::io::Error::last_os_error(),
            ));
        }
    }

    let proc_fd_path = format!("/proc/self/fd/{}", current_fd.as_raw_fd());
    let canonical_path = std::fs::read_link(&proc_fd_path).map_err(|e| {
        Error::IoContext(
            format!(
                "Security failure: cannot read magic symlink '{}' to get canonical path",
                proc_fd_path
            ),
            e,
        )
    })?;

    Ok(SecurePath {
        path: canonical_path.to_string_lossy().into_owned(),
        fd: current_fd,
    })
}

fn open_root() -> Result<OwnedFd, Error> {
    let c_root =
        std::ffi::CString::new("/").map_err(|_| Error::System("Nul byte in root path".into()))?;
    let fd = unsafe {
        libc::open(
            c_root.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(Error::IoContext(
            "Cannot open root".to_string(),
            std::io::Error::last_os_error(),
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn read_link_from_fd(link_fd: i32) -> Result<String, Error> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    let n = unsafe {
        libc::readlinkat(
            link_fd,
            c"".as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
        )
    };
    if n < 0 {
        return Err(Error::IoContext(
            "readlinkat on opened symlink failed".to_string(),
            std::io::Error::last_os_error(),
        ));
    }
    if n as usize == buf.len() {
        return Err(Error::Security("Symlink target too long".to_string()));
    }
    let s = std::str::from_utf8(&buf[..n as usize])
        .map_err(|_| Error::Parse("Invalid UTF-8 in symlink".into()))?;
    Ok(s.to_string())
}

fn check_blocked(path: &str, blocked_paths: &[String]) -> Result<(), Error> {
    for blocked in blocked_paths {
        let bp = Path::new(blocked);
        let cp = Path::new(path);
        if cp == bp || cp.starts_with(bp) {
            return Err(Error::Validation(format!(
                "Access to blocked path '{}' is denied",
                path
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ValidationContext;
    use tempfile::tempdir;

    #[test]
    fn test_check_path_blocks_traversal_via_symlink() {
        let dir = tempdir().unwrap();
        let base_path = dir.path();

        let secret_dir = base_path.join("secret");
        std::fs::create_dir(&secret_dir).unwrap();
        let secret_file = secret_dir.join("data.txt");
        std::fs::write(&secret_file, b"CONFIDENTIAL").unwrap();

        let public_dir = base_path.join("public");
        std::fs::create_dir(&public_dir).unwrap();

        // Create a malicious symlink: public/trap -> ../secret
        let trap_link = public_dir.join("trap");
        std::os::unix::fs::symlink("../secret", &trap_link).unwrap();

        let blocked_paths = vec![secret_dir.to_str().unwrap().to_string()];
        let context = ValidationContext::Positional;

        // Attempt to access public/trap/data.txt
        let target = trap_link.join("data.txt");
        let result = check_path(target.to_str().unwrap(), &context, &blocked_paths);

        assert!(result.is_err());
        assert!(
            result.as_ref().unwrap_err().to_string().contains("denied"),
            "Expected denial error, got {:?}",
            result
        );
    }

    #[test]
    fn test_check_path_blocks_traversal_via_explicit_dots() {
        let dir = tempdir().unwrap();
        let base_path = dir.path();

        let secret_dir = base_path.join("secret");
        std::fs::create_dir(&secret_dir).unwrap();

        let public_dir = base_path.join("public");
        std::fs::create_dir(&public_dir).unwrap();

        let blocked_paths = vec![secret_dir.to_str().unwrap().to_string()];
        let context = ValidationContext::Positional;

        let target = public_dir.join("..").join("secret");

        let result = check_path(target.to_str().unwrap(), &context, &blocked_paths);

        assert!(result.is_err());
    }

    #[test]
    fn test_check_path_allows_component_names_with_double_dots() {
        let dir = tempdir().unwrap();
        let base_path = dir.path();
        let safe_dir = base_path.join("safe..name");
        std::fs::create_dir(&safe_dir).unwrap();
        let safe_file = safe_dir.join("payload.txt");
        std::fs::write(&safe_file, b"ok").unwrap();

        let context = ValidationContext::Positional;
        let result = check_path(safe_file.to_str().unwrap(), &context, &[]);

        assert!(
            result.is_ok(),
            "Expected non-traversal component name to be allowed, got {:?}",
            result
        );
    }

    #[test]
    fn test_check_path_allows_safe_parent_dir_component_canonicalization() {
        let dir = tempdir().unwrap();
        let base_path = dir.path();
        let public_dir = base_path.join("public");
        std::fs::create_dir(&public_dir).unwrap();
        let payload = public_dir.join("payload.txt");
        std::fs::write(&payload, b"ok").unwrap();

        let parent_relative = public_dir.join("..").join("public").join("payload.txt");
        let expected = std::fs::canonicalize(&parent_relative)
            .unwrap()
            .to_string_lossy()
            .into_owned();

        let context = ValidationContext::Positional;
        let secure = check_path(parent_relative.to_str().unwrap(), &context, &[]).unwrap();

        assert_eq!(secure.path, expected);
    }

    #[test]
    fn test_read_link_from_fd_is_stable_after_symlink_swap() {
        use std::os::fd::{AsRawFd, FromRawFd};

        let dir = tempdir().unwrap();
        let link_path = dir.path().join("link");
        std::os::unix::fs::symlink("first-target", &link_path).unwrap();

        let c_link = std::ffi::CString::new(link_path.to_str().unwrap()).unwrap();
        let fd_raw = unsafe {
            libc::open(
                c_link.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        assert!(
            fd_raw >= 0,
            "failed to open symlink: {}",
            std::io::Error::last_os_error()
        );
        let link_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd_raw) };

        std::fs::remove_file(&link_path).unwrap();
        std::os::unix::fs::symlink("second-target", &link_path).unwrap();

        let target = read_link_from_fd(link_fd.as_raw_fd()).unwrap();
        assert_eq!(target, "first-target");
    }
}
