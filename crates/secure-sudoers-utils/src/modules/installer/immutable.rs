use secure_sudoers_common::error::Error as CommonError;
use secure_sudoers_common::fs::check_path;
use secure_sudoers_common::models::ValidationContext;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

type InodeFlags = libc::c_int;
const LINUX_FS_IMMUTABLE_FL: InodeFlags = 0x0000_0010;

#[derive(Debug)]
struct ImmutableOpError {
    message: String,
    raw_os_error: Option<i32>,
}

impl ImmutableOpError {
    fn new(message: String, raw_os_error: Option<i32>) -> Self {
        Self {
            message,
            raw_os_error,
        }
    }

    fn from_io_context(context: String, error: std::io::Error) -> Self {
        let raw_os_error = error.raw_os_error();
        Self {
            message: format!("{context}: {error}"),
            raw_os_error,
        }
    }

    fn from_common_context(context: String, error: CommonError) -> Self {
        let raw_os_error = match &error {
            CommonError::Io(err) | CommonError::IoContext(_, err) => err.raw_os_error(),
            _ => None,
        };
        Self {
            message: format!("{context}: {error}"),
            raw_os_error,
        }
    }
}

fn immutable_action_for_flag(flag: &str) -> Result<bool, String> {
    match flag {
        "+i" => Ok(true),
        "-i" => Ok(false),
        _ => Err(format!("Unsupported immutable operation flag: {flag}")),
    }
}

fn open_verified_target(path: &str) -> Result<std::fs::File, ImmutableOpError> {
    let path_obj = Path::new(path);
    if !path_obj.is_absolute() {
        return Err(ImmutableOpError::new(
            format!("Immutable operation requires an absolute path: {path}"),
            None,
        ));
    }

    let parent = path_obj.parent().ok_or_else(|| {
        ImmutableOpError::new(
            format!("Cannot determine parent directory for immutable target {path}"),
            None,
        )
    })?;
    let parent_str = parent.to_str().ok_or_else(|| {
        ImmutableOpError::new(
            format!("Parent directory for immutable target {path} is not valid UTF-8"),
            None,
        )
    })?;
    let secure_parent =
        check_path(parent_str, &ValidationContext::Positional, &[]).map_err(|e| {
            ImmutableOpError::from_common_context(
                format!(
                    "Cannot securely resolve parent directory of {path} before immutable operation"
                ),
                e,
            )
        })?;

    let basename = path_obj.file_name().ok_or_else(|| {
        ImmutableOpError::new(
            format!("Immutable operation requires a concrete target path, got: {path}"),
            None,
        )
    })?;
    let basename_c = std::ffi::CString::new(basename.as_bytes()).map_err(|_| {
        ImmutableOpError::new(
            format!("Immutable target contains an interior NUL byte: {path}"),
            None,
        )
    })?;

    let fd = unsafe {
        libc::openat(
            secure_parent.fd.as_raw_fd(),
            basename_c.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd >= 0 {
        return Ok(unsafe { std::fs::File::from_raw_fd(fd) });
    }

    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ELOOP) {
        return Err(ImmutableOpError::new(
            format!("Refusing immutable operation on symbolic link target {path}"),
            Some(libc::ELOOP),
        ));
    }

    Err(ImmutableOpError::from_io_context(
        format!("Cannot open secure target {path} for immutable operation"),
        error,
    ))
}

fn read_inode_flags(target: &std::fs::File, path: &str) -> Result<InodeFlags, ImmutableOpError> {
    let mut flags: InodeFlags = 0;
    let rc = unsafe { libc::ioctl(target.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut flags) };
    if rc == 0 {
        return Ok(flags);
    }

    Err(ImmutableOpError::from_io_context(
        format!("Cannot read inode flags for {path} via ioctl(FS_IOC_GETFLAGS)"),
        std::io::Error::last_os_error(),
    ))
}

fn write_inode_flags(
    target: &std::fs::File,
    path: &str,
    flags: InodeFlags,
) -> Result<(), ImmutableOpError> {
    let updated = flags;
    let rc = unsafe {
        libc::ioctl(
            target.as_raw_fd(),
            libc::FS_IOC_SETFLAGS,
            &updated as *const InodeFlags,
        )
    };
    if rc == 0 {
        return Ok(());
    }

    Err(ImmutableOpError::from_io_context(
        format!("Cannot write inode flags for {path} via ioctl(FS_IOC_SETFLAGS)"),
        std::io::Error::last_os_error(),
    ))
}

fn with_immutable_bit(flags: InodeFlags, set_immutable: bool) -> InodeFlags {
    if set_immutable {
        flags | LINUX_FS_IMMUTABLE_FL
    } else {
        flags & !LINUX_FS_IMMUTABLE_FL
    }
}

fn apply_immutable_flag(path: &str, set_immutable: bool) -> Result<(), ImmutableOpError> {
    let target = open_verified_target(path)?;
    let current_flags = read_inode_flags(&target, path)?;
    let updated_flags = with_immutable_bit(current_flags, set_immutable);
    if updated_flags == current_flags {
        return Ok(());
    }
    write_inode_flags(&target, path, updated_flags)
}

pub(crate) fn chattr_op(flag: &str, paths: &[&str]) -> Vec<String> {
    if paths.is_empty() {
        return Vec::new();
    }

    let set_immutable = match immutable_action_for_flag(flag) {
        Ok(set_immutable) => set_immutable,
        Err(e) => return vec![e],
    };

    let mut errors = Vec::new();
    for path in paths {
        if let Err(e) = apply_immutable_flag(path, set_immutable) {
            if !set_immutable && e.raw_os_error == Some(libc::ENOENT) {
                continue;
            }
            errors.push(e.message);
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::{
        InodeFlags, LINUX_FS_IMMUTABLE_FL, chattr_op, open_verified_target, with_immutable_bit,
    };
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    use tempfile::tempdir;

    #[test]
    fn test_open_verified_target_holds_original_inode_after_path_swap() {
        let dir = tempdir().unwrap();
        let original = dir.path().join("original");
        let swapped = dir.path().join("swapped");
        let managed = dir.path().join("managed");
        std::fs::write(&original, b"one").unwrap();
        std::fs::write(&swapped, b"two").unwrap();
        std::fs::hard_link(&original, &managed).unwrap();

        let target = open_verified_target(managed.to_str().unwrap()).unwrap();
        std::fs::remove_file(&managed).unwrap();
        std::os::unix::fs::symlink(&swapped, &managed).unwrap();

        let fd_meta = std::fs::metadata(format!("/proc/self/fd/{}", target.as_raw_fd())).unwrap();
        let original_meta = std::fs::metadata(&original).unwrap();
        let swapped_meta = std::fs::metadata(&swapped).unwrap();

        assert_eq!(fd_meta.dev(), original_meta.dev());
        assert_eq!(fd_meta.ino(), original_meta.ino());
        assert_ne!(
            (fd_meta.dev(), fd_meta.ino()),
            (swapped_meta.dev(), swapped_meta.ino())
        );
    }

    #[test]
    fn test_open_verified_target_rejects_symlink_target() {
        let dir = tempdir().unwrap();
        let original = dir.path().join("original");
        let managed = dir.path().join("managed");
        std::fs::write(&original, b"one").unwrap();
        std::os::unix::fs::symlink(&original, &managed).unwrap();

        let err = open_verified_target(managed.to_str().unwrap())
            .expect_err("symlink target should be rejected to match chattr no-follow behavior");
        assert!(
            err.message.contains("symbolic link"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_chattr_op_rejects_unsupported_flag() {
        let errors = chattr_op("+a", &["/tmp/unused"]);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("Unsupported immutable operation flag"));
    }

    #[test]
    fn test_chattr_op_skips_missing_target_on_unlock() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("missing");
        let errors = chattr_op("-i", &[missing.to_str().unwrap()]);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_chattr_op_reports_missing_target_on_install() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("missing");
        let errors = chattr_op("+i", &[missing.to_str().unwrap()]);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("Cannot open secure target"));
    }

    #[test]
    fn test_with_immutable_bit_is_noop_when_already_set() {
        let flags = LINUX_FS_IMMUTABLE_FL;
        assert_eq!(with_immutable_bit(flags, true), flags);
    }

    #[test]
    fn test_with_immutable_bit_is_noop_when_already_unset() {
        let flags: InodeFlags = 0;
        assert_eq!(with_immutable_bit(flags, false), flags);
    }
}
