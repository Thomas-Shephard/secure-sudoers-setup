use super::path_guard::{ensure_path_matches_fd, fstat_for_fd, proc_fd_path, safe_traverse};
use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, unshare};
use secure_sudoers_common::error::Error;
use secure_sudoers_common::models::IsolationSettings;
use std::io::Error as IoError;
use std::os::fd::AsRawFd;

pub(super) fn mount_shadow_fd(fd: i32, original_path: &str) -> Result<(), Error> {
    mount_shadow_fd_with(fd, original_path, |source, target, fstype, flags| {
        mount(source, target, fstype, flags, None::<&str>).map_err(IoError::from)
    })
}

pub(super) fn mount_shadow_fd_with<MountFn>(
    fd: i32,
    original_path: &str,
    mut mount_fn: MountFn,
) -> Result<(), Error>
where
    MountFn: FnMut(Option<&str>, &str, Option<&str>, MsFlags) -> Result<(), IoError>,
{
    let st = fstat_for_fd(fd, original_path)?;
    // Re-verify the path binding immediately before mount to fail closed on path-swap races.
    ensure_path_matches_fd(original_path, fd)?;
    let mount_target = proc_fd_path(fd);
    let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;

    if is_dir {
        mount_fn(
            Some("tmpfs"),
            mount_target.as_str(),
            Some("tmpfs"),
            MsFlags::empty(),
        )
        .map_err(|e| {
            Error::IoContext(
                format!(
                    "Security failure: tmpfs mount on blocked dir '{}' failed",
                    original_path
                ),
                IoError::from(e),
            )
        })?;
    } else {
        mount_fn(
            Some("/dev/null"),
            mount_target.as_str(),
            None::<&str>,
            MsFlags::MS_BIND,
        )
        .map_err(|e| {
            Error::IoContext(
                format!(
                    "Security failure: bind mount /dev/null on blocked file '{}' failed",
                    original_path
                ),
                IoError::from(e),
            )
        })?;
    }
    Ok(())
}

pub(super) fn apply_blocked_paths(paths: &[String]) -> Result<(), Error> {
    for path_str in paths {
        let fd = safe_traverse(path_str, true)?;
        mount_shadow_fd(fd.as_raw_fd(), path_str)?;
    }
    Ok(())
}

pub(super) fn unshare_namespaces(settings: &IsolationSettings) -> Result<(), Error> {
    let mut flags = CloneFlags::CLONE_NEWNS;
    if settings.unshare_network {
        flags |= CloneFlags::CLONE_NEWNET;
    }
    if settings.unshare_pid {
        flags |= CloneFlags::CLONE_NEWPID;
    }
    if settings.unshare_ipc {
        flags |= CloneFlags::CLONE_NEWIPC;
    }
    if settings.unshare_uts {
        flags |= CloneFlags::CLONE_NEWUTS;
    }
    unshare(flags)
        .map_err(|e| Error::IoContext(format!("unshare({flags:?}) failed"), IoError::from(e)))
}

pub(super) fn make_root_private() -> Result<(), Error> {
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| {
        Error::IoContext(
            "remount '/' as MS_PRIVATE|MS_REC failed".to_string(),
            IoError::from(e),
        )
    })
}

pub(super) fn apply_private_mounts(paths: &[String]) -> Result<(), Error> {
    apply_private_mounts_with(
        paths,
        |_| Ok(()),
        |source, target, fstype, flags| {
            mount(source, target, fstype, flags, None::<&str>)
                .map_err(|e| Error::Io(IoError::from(e)))
        },
    )
}

pub(super) fn apply_private_mounts_with<BeforeMount, MountFn>(
    paths: &[String],
    mut before_mount: BeforeMount,
    mut mount_fn: MountFn,
) -> Result<(), Error>
where
    BeforeMount: FnMut(&str) -> Result<(), Error>,
    MountFn: FnMut(Option<&str>, &str, Option<&str>, MsFlags) -> Result<(), Error>,
{
    for path_str in paths {
        let fd = safe_traverse(path_str, false)?;
        before_mount(path_str)?;
        ensure_path_matches_fd(path_str, fd.as_raw_fd())?;
        let mount_target = proc_fd_path(fd.as_raw_fd());
        mount_fn(
            Some("tmpfs"),
            mount_target.as_str(),
            Some("tmpfs"),
            MsFlags::empty(),
        )?;
    }
    Ok(())
}

pub(super) fn apply_readonly_mounts(paths: &[String]) -> Result<(), Error> {
    apply_readonly_mounts_with(
        paths,
        |_| Ok(()),
        |source, target, fstype, flags| {
            mount(source, target, fstype, flags, None::<&str>)
                .map_err(|e| Error::Io(IoError::from(e)))
        },
    )
}

pub(super) fn apply_readonly_mounts_with<BeforeMount, MountFn>(
    paths: &[String],
    mut before_mount: BeforeMount,
    mut mount_fn: MountFn,
) -> Result<(), Error>
where
    BeforeMount: FnMut(&str) -> Result<(), Error>,
    MountFn: FnMut(Option<&str>, &str, Option<&str>, MsFlags) -> Result<(), Error>,
{
    for path_str in paths {
        let fd = safe_traverse(path_str, false)?;
        before_mount(path_str)?;
        ensure_path_matches_fd(path_str, fd.as_raw_fd())?;
        let mount_source = proc_fd_path(fd.as_raw_fd());
        mount_fn(
            Some(mount_source.as_str()),
            mount_source.as_str(),
            None,
            MsFlags::MS_BIND,
        )?;

        mount_fn(
            Some(mount_source.as_str()),
            mount_source.as_str(),
            None,
            MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY,
        )?;
    }
    Ok(())
}
