use super::path_guard::{
    ensure_path_matches_fd, ensure_path_matches_fd_with_stat, fstat_for_fd, proc_fd_path,
    safe_traverse,
};
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
                e,
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
                e,
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

pub(super) fn pin_validated_path_argument(fd: i32, canonical_path: &str) -> Result<(), Error> {
    pin_validated_path_argument_with(
        fd,
        canonical_path,
        |_| Ok(()),
        |source, target, fstype, flags| {
            mount(source, target, fstype, flags, None::<&str>).map_err(IoError::from)
        },
    )
}

pub(super) fn pin_validated_path_argument_with<BeforeMount, MountFn>(
    fd: i32,
    canonical_path: &str,
    mut before_mount: BeforeMount,
    mut mount_fn: MountFn,
) -> Result<(), Error>
where
    BeforeMount: FnMut(&str) -> Result<(), Error>,
    MountFn: FnMut(Option<&str>, &str, Option<&str>, MsFlags) -> Result<(), IoError>,
{
    let source_stat = fstat_for_fd(fd, canonical_path)?;
    // Run any setup hook first, then capture the current target with one secure
    // traversal and compare it to the validated source inode.
    before_mount(canonical_path)?;
    let target_fd = safe_traverse(canonical_path, false)?;

    let target_stat = fstat_for_fd(target_fd.as_raw_fd(), canonical_path)?;
    if source_stat.st_dev != target_stat.st_dev || source_stat.st_ino != target_stat.st_ino {
        return Err(Error::Security(format!(
            "Security failure: path '{}' no longer matches the validated argument",
            canonical_path
        )));
    }

    // The validated argument FD may have been opened before unshare(CLONE_NEWNS).
    // Use the freshly traversed FD from this namespace as bind source/target, and
    // rely on the inode/device comparison plus final ensure_path_matches_fd check
    // to guarantee it still matches the originally validated object.
    let mount_source = proc_fd_path(target_fd.as_raw_fd());
    let mount_target = proc_fd_path(target_fd.as_raw_fd());
    // Keep source+target FD-anchored. Using the raw path string as mount target
    // would reintroduce a path-resolution race between verification and mount.
    // The final ensure_path_matches_fd check confirms canonical_path still binds
    // to the validated inode after the bind mount is installed.
    mount_fn(
        Some(mount_source.as_str()),
        mount_target.as_str(),
        None::<&str>,
        MsFlags::MS_BIND,
    )
    .map_err(|e| {
        Error::IoContext(
            format!(
                "Security failure: bind-mount pinning failed for '{}'",
                canonical_path
            ),
            e,
        )
    })?;

    // Final check: the visible argument path must still resolve to the same
    // validated inode immediately before delegated exec.
    ensure_path_matches_fd(canonical_path, fd)?;
    Ok(())
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
        // Intentionally re-validate immediately before bind to fail closed on
        // swaps that can occur after fd capture and before mount syscall.
        let initial_stat = ensure_path_matches_fd_with_stat(path_str, fd.as_raw_fd())?;
        let mount_source = proc_fd_path(fd.as_raw_fd());
        // Intentionally self-bind the fd path: this promotes the target to a
        // mountpoint while keeping both source and target fd-anchored.
        mount_fn(
            Some(mount_source.as_str()),
            mount_source.as_str(),
            None,
            MsFlags::MS_BIND,
        )?;

        // Re-open after the bind mount so remount targets the current mountpoint
        // rather than the pre-bind mount referenced by the original fd.
        let remount_fd = safe_traverse(path_str, false)?;
        // Re-validate again to detect swaps between remount_fd acquisition and
        // remount use, then compare inode/device continuity across phases.
        let remount_stat = ensure_path_matches_fd_with_stat(path_str, remount_fd.as_raw_fd())?;
        if initial_stat.st_dev != remount_stat.st_dev || initial_stat.st_ino != remount_stat.st_ino
        {
            return Err(Error::Security(format!(
                "Security failure: path '{}' changed between bind and remount",
                path_str
            )));
        }
        let remount_target = proc_fd_path(remount_fd.as_raw_fd());
        mount_fn(
            None::<&str>,
            remount_target.as_str(),
            None,
            MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY,
        )?;
    }
    Ok(())
}
