pub(crate) mod capabilities;
mod mounts;
mod path_guard;

use secure_sudoers_common::error::Error;
use secure_sudoers_common::models::IsolationSettings;
use std::path::Path;

#[cfg(test)]
use capabilities::{drop_bounding_capabilities_with, drop_capabilities, parse_cap_last_cap};
#[cfg(test)]
use mounts::{
    apply_private_mounts_with, apply_readonly_mounts_with, mount_shadow_fd, mount_shadow_fd_with,
    pin_validated_path_argument_with,
};
#[cfg(test)]
use nix::mount::{MsFlags, mount};
#[cfg(test)]
use nix::sched::{CloneFlags, unshare};
#[cfg(test)]
use path_guard::{ensure_path_matches_fd, safe_traverse};
#[cfg(test)]
use std::os::fd::AsRawFd;

pub fn setup_isolation(
    settings: &IsolationSettings,
    blocked_paths: &[String],
) -> Result<(), Error> {
    mounts::unshare_namespaces(settings)?;
    mounts::make_root_private()?;
    mounts::apply_private_mounts(&settings.private_mounts)?;
    mounts::apply_blocked_paths(blocked_paths)?;
    mounts::apply_readonly_mounts(&settings.readonly_mounts)?;
    Ok(())
}

pub(crate) fn canonical_parent_path(canonical_path: &str) -> Result<&str, Error> {
    let parent_path = Path::new(canonical_path).parent().ok_or_else(|| {
        Error::Validation(format!(
            "Path '{}' has no parent for pinning",
            canonical_path
        ))
    })?;
    Ok(parent_path
        .to_str()
        .expect("parent of valid UTF-8 path must be UTF-8"))
}

pub(crate) fn pin_validated_path_parent(parent_path: &str) -> Result<(), Error> {
    mounts::pin_validated_path_parent(parent_path)
}

pub(crate) fn pin_path_at_fd(fd: i32, canonical_path: &str) -> Result<(), Error> {
    mounts::pin_path_at_fd(fd, canonical_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::require_root;
    use crate::testing::in_fork;
    use secure_sudoers_common::fs::check_path;
    use secure_sudoers_common::models::{IsolationSettings, ValidationContext};

    fn mount_only_settings() -> IsolationSettings {
        IsolationSettings {
            unshare_network: false,
            unshare_pid: false,
            unshare_ipc: false,
            unshare_uts: false,
            private_mounts: vec![],
            readonly_mounts: vec![],
        }
    }

    use std::sync::Mutex;
    static GLOBAL_PATH: Mutex<Option<String>> = Mutex::new(None);

    fn pin_parent_chain_for_path(canonical_path: &str) -> Result<(), Error> {
        if canonical_path == "/" {
            return Ok(());
        }
        let mut parent_chain = Vec::<&str>::new();
        let mut current_path = canonical_path;
        loop {
            let parent_path = canonical_parent_path(current_path)?;
            if parent_path == "/" {
                break;
            }
            parent_chain.push(parent_path);
            current_path = parent_path;
        }
        for parent_path in parent_chain.into_iter().rev() {
            pin_validated_path_parent(parent_path)?;
        }
        Ok(())
    }

    #[test]
    fn test_setup_isolation_blocks_path() {
        require_root!();

        let secret_path = format!("/tmp/ss_isolation_secret_{}", std::process::id());
        let _ = std::fs::remove_file(&secret_path);
        std::fs::write(&secret_path, b"TOP SECRET CONTENT").expect("write temp file");

        *GLOBAL_PATH.lock().unwrap() = Some(secret_path.clone());

        fn child_fn() -> bool {
            let guard = GLOBAL_PATH.lock().unwrap();
            let secret_path = guard.as_ref().unwrap();
            let settings = mount_only_settings();
            match setup_isolation(&settings, std::slice::from_ref(secret_path)) {
                Err(e) => {
                    eprintln!("  setup_isolation failed: {e}");
                    false
                }
                Ok(()) => {
                    let content = std::fs::read(secret_path).unwrap_or_default();
                    content.is_empty()
                }
            }
        }

        let ok = unsafe { in_fork(child_fn) };

        let _ = std::fs::remove_file(&secret_path);
        assert!(ok, "setup_isolation should have masked the blocked file");
    }

    #[test]
    fn test_setup_isolation_readonly_mount() {
        require_root!();

        let dir = tempfile::TempDir::new().expect("tempdir");
        let dir_path = dir.path().to_str().unwrap().to_string();
        std::fs::write(format!("{dir_path}/existing.txt"), b"data").unwrap();

        *GLOBAL_PATH.lock().unwrap() = Some(dir_path);

        fn child_fn() -> bool {
            let guard = GLOBAL_PATH.lock().unwrap();
            let dir_path = guard.as_ref().unwrap();
            let settings = IsolationSettings {
                unshare_network: false,
                unshare_pid: false,
                unshare_ipc: false,
                unshare_uts: false,
                private_mounts: vec![],
                readonly_mounts: vec![dir_path.clone()],
            };
            match setup_isolation(&settings, &[]) {
                Err(e) => {
                    eprintln!("  setup_isolation failed: {e}");
                    false
                }
                Ok(()) => {
                    let write_result = std::fs::write(format!("{dir_path}/new.txt"), b"new");
                    write_result.is_err()
                }
            }
        }

        let ok = unsafe { in_fork(child_fn) };
        assert!(ok, "write to read-only mount should have failed");
    }

    #[test]
    fn test_setup_isolation_does_not_pre_drop_capabilities() {
        require_root!();

        fn child_fn() -> bool {
            let settings = mount_only_settings();
            match setup_isolation(&settings, &[]) {
                Err(e) => {
                    eprintln!("  setup_isolation failed: {e}");
                    false
                }
                Ok(()) => match drop_capabilities() {
                    Ok(()) => true,
                    Err(e) => {
                        eprintln!("  explicit drop_capabilities failed after setup_isolation: {e}");
                        false
                    }
                },
            }
        }

        let ok = unsafe { in_fork(child_fn) };
        assert!(
            ok,
            "setup_isolation should not pre-drop capabilities before explicit drop"
        );
    }

    #[test]
    fn test_drop_capabilities_clears_all_sets() {
        require_root!();

        fn child_fn() -> bool {
            match drop_capabilities() {
                Err(e) => {
                    eprintln!("  drop_capabilities failed: {e}");
                    false
                }
                Ok(()) => {
                    let status = std::fs::read_to_string("/proc/self/status")
                        .expect("read /proc/self/status");
                    let cap_eff = status
                        .lines()
                        .find(|l| l.starts_with("CapEff:"))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .and_then(|v| u64::from_str_radix(v, 16).ok())
                        .unwrap_or(u64::MAX);
                    let cap_prm = status
                        .lines()
                        .find(|l| l.starts_with("CapPrm:"))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .and_then(|v| u64::from_str_radix(v, 16).ok())
                        .unwrap_or(u64::MAX);
                    cap_eff == 0 && cap_prm == 0
                }
            }
        }

        let ok = unsafe { in_fork(child_fn) };
        assert!(
            ok,
            "drop_capabilities should zero all effective and permitted sets"
        );
    }

    #[test]
    fn test_drop_capabilities_fails_closed_on_bounding_drop_error() {
        require_root!();

        fn child_fn() -> bool {
            if let Err(e) = drop_capabilities() {
                eprintln!("  initial drop_capabilities failed unexpectedly: {e}");
                return false;
            }

            match drop_capabilities() {
                Ok(()) => {
                    eprintln!("  expected second drop_capabilities to fail");
                    false
                }
                Err(e) => e
                    .to_string()
                    .contains("Security failure: PR_CAPBSET_DROP failed for capability 0"),
            }
        }

        let ok = unsafe { in_fork(child_fn) };
        assert!(
            ok,
            "drop_capabilities should fail when PR_CAPBSET_DROP is denied"
        );
    }

    #[test]
    fn test_drop_bounding_capabilities_reports_failing_index() {
        let err = drop_bounding_capabilities_with(5, |cap| {
            if cap == 3 {
                Err(std::io::Error::from_raw_os_error(libc::EPERM))
            } else {
                Ok(())
            }
        })
        .expect_err("drop_bounding_capabilities_with should fail on injected EPERM");
        assert!(
            err.to_string()
                .contains("PR_CAPBSET_DROP failed for capability 3")
        );
    }

    #[test]
    fn test_parse_cap_last_cap_accepts_trimmed_numeric_values() {
        assert_eq!(parse_cap_last_cap("40\n").unwrap(), 40);
    }

    #[test]
    fn test_parse_cap_last_cap_rejects_invalid_values() {
        let err = parse_cap_last_cap("not-a-number")
            .expect_err("parse_cap_last_cap should reject non-numeric input");
        assert!(
            err.to_string()
                .contains("invalid /proc/sys/kernel/cap_last_cap value")
        );
    }

    #[test]
    fn test_setup_isolation_rejects_symlink_blocked_path() {
        require_root!();

        let link_path = format!("/tmp/ss_symlink_trap_{}", std::process::id());
        let _ = std::fs::remove_file(&link_path);
        std::os::unix::fs::symlink("/etc/hostname", &link_path).expect("create symlink");

        *GLOBAL_PATH.lock().unwrap() = Some(link_path.clone());

        fn child_fn() -> bool {
            let guard = GLOBAL_PATH.lock().unwrap();
            let link_path = guard.as_ref().unwrap();
            let settings = mount_only_settings();
            let res = setup_isolation(&settings, std::slice::from_ref(link_path));
            matches!(
                res,
                Err(ref e) if e.to_string().contains("symlink detected")
            )
        }

        let ok = unsafe { in_fork(child_fn) };
        let _ = std::fs::remove_file(&link_path);
        assert!(ok, "setup_isolation must reject symlinks in blocked_paths");
    }

    #[test]
    fn test_path_swapping_mitigation() {
        require_root!();

        let target_path = format!("/tmp/ss_swappable_{}", std::process::id());
        let _ = std::fs::remove_file(&target_path);
        std::fs::write(&target_path, b"ORIGINAL").unwrap();

        let swapper_path = target_path.clone();

        fn child_fn() -> bool {
            let target_path = format!("/tmp/ss_swappable_{}", nix::unistd::getppid());

            // Real isolation uses private mount namespace
            if let Err(e) = unshare(CloneFlags::CLONE_NEWNS) {
                eprintln!("unshare failed: {e}");
                return false;
            }
            if let Err(e) = mount(
                None::<&str>,
                "/",
                None::<&str>,
                MsFlags::MS_PRIVATE | MsFlags::MS_REC,
                None::<&str>,
            ) {
                eprintln!("mount private failed: {e}");
                return false;
            }

            let fd = match safe_traverse(&target_path, false) {
                Ok(fd) => fd,
                Err(e) => {
                    eprintln!("safe_traverse failed: {e}");
                    return false;
                }
            };

            let _ = std::fs::remove_file(&target_path);
            std::os::unix::fs::symlink("/etc/hostname", &target_path).unwrap();

            match ensure_path_matches_fd(&target_path, fd.as_raw_fd()) {
                Err(e)
                    if e.to_string().contains("symlink detected")
                        || e.to_string()
                            .contains("does not match the expected file descriptor")
                        || e.to_string().contains("changed after verification") =>
                {
                    true
                }
                Err(e) => {
                    eprintln!("unexpected error: {e}");
                    false
                }
                Ok(()) => {
                    eprintln!("path swap went undetected");
                    false
                }
            }
        }

        let ok = unsafe { in_fork(child_fn) };
        let _ = std::fs::remove_file(&swapper_path);
        assert!(ok, "Isolation must be safe in a private mount namespace");
    }

    #[test]
    fn test_apply_private_mounts_rejects_path_swap_before_mount() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let base_path = dir.path().join("target");
        let moved_path = dir.path().join("target.moved");
        let attacker_path = dir.path().join("target.attacker");
        std::fs::create_dir(&base_path).expect("create base dir");
        std::fs::create_dir(&attacker_path).expect("create attacker dir");

        let base_path = base_path.to_string_lossy().to_string();
        let moved_path = moved_path.to_string_lossy().to_string();
        let attacker_path = attacker_path.to_string_lossy().to_string();
        let paths = vec![base_path.clone()];
        let mut calls = 0usize;

        let result = apply_private_mounts_with(
            &paths,
            |path| {
                assert_eq!(path, base_path.as_str());
                std::fs::rename(&base_path, &moved_path).map_err(|e| {
                    secure_sudoers_common::error::Error::IoContext(
                        "rename base->moved failed".to_string(),
                        e,
                    )
                })?;
                std::fs::rename(&attacker_path, &base_path).map_err(|e| {
                    secure_sudoers_common::error::Error::IoContext(
                        "rename attacker->base failed".to_string(),
                        e,
                    )
                })?;
                Ok(())
            },
            |_source, _target, _fstype, _flags| {
                calls += 1;
                Ok(())
            },
        );

        let err = result.expect_err("private mount should fail closed after path swap");
        assert!(
            err.to_string()
                .contains("does not match the expected file descriptor")
                || err.to_string().contains("changed after verification")
                || err.to_string().contains("symlink detected"),
            "unexpected error: {err}"
        );
        assert_eq!(calls, 0, "mount should not be attempted after path swap");
    }

    #[test]
    fn test_apply_private_mounts_uses_fd_anchored_target() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let base_path = dir.path().join("target");
        std::fs::create_dir(&base_path).expect("create base dir");

        let base_path = base_path.to_string_lossy().to_string();
        let paths = vec![base_path.clone()];
        let mut seen_target = None::<String>;

        apply_private_mounts_with(
            &paths,
            |_| Ok(()),
            |source, target, fstype, flags| {
                assert_eq!(source, Some("tmpfs"));
                assert_eq!(fstype, Some("tmpfs"));
                assert_eq!(flags, MsFlags::empty());
                seen_target = Some(target.to_string());
                Ok(())
            },
        )
        .expect("private mount setup should succeed");

        let seen_target = seen_target.expect("mount callback should be called");
        assert!(
            seen_target.starts_with("/proc/self/fd/"),
            "private mount target should be fd-anchored, got '{seen_target}'"
        );
        assert_ne!(
            seen_target, base_path,
            "private mount target should not use the raw path string"
        );
    }

    #[test]
    fn test_apply_readonly_mounts_rejects_path_swap_before_mount() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let base_path = dir.path().join("target");
        let moved_path = dir.path().join("target.moved");
        let attacker_path = dir.path().join("target.attacker");
        std::fs::create_dir(&base_path).expect("create base dir");
        std::fs::create_dir(&attacker_path).expect("create attacker dir");

        let base_path = base_path.to_string_lossy().to_string();
        let moved_path = moved_path.to_string_lossy().to_string();
        let attacker_path = attacker_path.to_string_lossy().to_string();
        let paths = vec![base_path.clone()];
        let mut calls = 0usize;

        let result = apply_readonly_mounts_with(
            &paths,
            |path| {
                assert_eq!(path, base_path.as_str());
                std::fs::rename(&base_path, &moved_path).map_err(|e| {
                    secure_sudoers_common::error::Error::IoContext(
                        "rename base->moved failed".to_string(),
                        e,
                    )
                })?;
                std::fs::rename(&attacker_path, &base_path).map_err(|e| {
                    secure_sudoers_common::error::Error::IoContext(
                        "rename attacker->base failed".to_string(),
                        e,
                    )
                })?;
                Ok(())
            },
            |_source, _target, _fstype, _flags| {
                calls += 1;
                Ok(())
            },
        );

        let err = result.expect_err("readonly mount should fail closed after path swap");
        assert!(
            err.to_string()
                .contains("does not match the expected file descriptor")
                || err.to_string().contains("changed after verification")
                || err.to_string().contains("symlink detected"),
            "unexpected error: {err}"
        );
        assert_eq!(calls, 0, "mount should not be attempted after path swap");
    }

    #[test]
    fn test_apply_readonly_mounts_uses_fd_anchored_target() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let base_path = dir.path().join("target");
        std::fs::create_dir(&base_path).expect("create base dir");

        let base_path = base_path.to_string_lossy().to_string();
        let paths = vec![base_path.clone()];
        let mut calls = Vec::<(Option<String>, String, MsFlags)>::new();

        apply_readonly_mounts_with(
            &paths,
            |_| Ok(()),
            |source, target, _fstype, flags| {
                calls.push((source.map(str::to_owned), target.to_string(), flags));
                Ok(())
            },
        )
        .expect("readonly mount setup should succeed");

        assert_eq!(calls.len(), 2, "readonly setup should issue bind + remount");
        let bind_source = calls[0]
            .0
            .as_deref()
            .expect("bind source should be provided");
        assert!(
            bind_source.starts_with("/proc/self/fd/"),
            "bind source should be fd-anchored, got '{bind_source}'"
        );
        assert!(
            calls[0].1.starts_with("/proc/self/fd/"),
            "bind target should be fd-anchored, got '{}'",
            calls[0].1
        );
        assert_eq!(
            bind_source, calls[0].1,
            "bind source/target should anchor to the same fd path"
        );
        assert_ne!(
            &calls[0].1, &base_path,
            "bind target should not use the raw path string"
        );

        assert!(
            calls[1].0.is_none(),
            "remount should not require a source path"
        );
        assert!(
            calls[1].1.starts_with("/proc/self/fd/"),
            "remount target should be fd-anchored, got '{}'",
            calls[1].1
        );
        assert_ne!(
            &calls[1].1, &base_path,
            "remount target should not use the raw path string"
        );
        assert_ne!(
            calls[0].1, calls[1].1,
            "remount should use a refreshed fd path after bind"
        );
        assert_eq!(calls[0].2, MsFlags::MS_BIND);
        assert_eq!(
            calls[1].2,
            MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY
        );
    }

    #[test]
    fn test_apply_readonly_mounts_rejects_path_swap_between_bind_and_remount() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let base_path = dir.path().join("target");
        let moved_path = dir.path().join("target.moved");
        let attacker_path = dir.path().join("target.attacker");
        std::fs::create_dir(&base_path).expect("create base dir");
        std::fs::create_dir(&attacker_path).expect("create attacker dir");

        let base_path = base_path.to_string_lossy().to_string();
        let moved_path = moved_path.to_string_lossy().to_string();
        let attacker_path = attacker_path.to_string_lossy().to_string();
        let paths = vec![base_path.clone()];
        let mut calls = 0usize;

        let result = apply_readonly_mounts_with(
            &paths,
            |_| Ok(()),
            |_source, _target, _fstype, _flags| {
                calls += 1;
                if calls == 1 {
                    std::fs::rename(&base_path, &moved_path).map_err(|e| {
                        secure_sudoers_common::error::Error::IoContext(
                            "rename base->moved failed".to_string(),
                            e,
                        )
                    })?;
                    std::fs::rename(&attacker_path, &base_path).map_err(|e| {
                        secure_sudoers_common::error::Error::IoContext(
                            "rename attacker->base failed".to_string(),
                            e,
                        )
                    })?;
                }
                Ok(())
            },
        );

        let err =
            result.expect_err("readonly mount should fail closed after bind/remount path swap");
        assert!(
            err.to_string().contains("changed between bind and remount"),
            "unexpected error: {err}"
        );
        assert_eq!(calls, 1, "remount should not be attempted after path swap");
    }

    #[test]
    fn test_mount_shadow_fd_uses_fd_anchored_target_for_file() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let base_path = dir.path().join("target");
        std::fs::write(&base_path, b"ORIGINAL").expect("write base path");

        let base_path = base_path.to_string_lossy().to_string();
        let fd = safe_traverse(&base_path, false).expect("safe_traverse");
        let mut call = None::<(Option<String>, String, Option<String>, MsFlags)>;

        mount_shadow_fd_with(
            fd.as_raw_fd(),
            &base_path,
            |source, target, fstype, flags| {
                call = Some((
                    source.map(str::to_owned),
                    target.to_string(),
                    fstype.map(str::to_owned),
                    flags,
                ));
                Ok::<(), std::io::Error>(())
            },
        )
        .expect("shadow mount setup should succeed");

        let (source, target, fstype, flags) = call.expect("mount callback should be called");
        assert_eq!(source.as_deref(), Some("/dev/null"));
        assert_eq!(fstype.as_deref(), None);
        assert_eq!(flags, MsFlags::MS_BIND);
        assert!(
            target.starts_with("/proc/self/fd/"),
            "shadow mount target should be fd-anchored, got '{target}'"
        );
        assert_ne!(
            target, base_path,
            "shadow mount target should not use the raw path string"
        );
    }

    #[test]
    fn test_mount_shadow_fd_uses_fd_anchored_target_for_directory() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let base_path = dir.path().join("target");
        std::fs::create_dir(&base_path).expect("create base dir");

        let base_path = base_path.to_string_lossy().to_string();
        let fd = safe_traverse(&base_path, false).expect("safe_traverse");
        let mut call = None::<(Option<String>, String, Option<String>, MsFlags)>;

        mount_shadow_fd_with(
            fd.as_raw_fd(),
            &base_path,
            |source, target, fstype, flags| {
                call = Some((
                    source.map(str::to_owned),
                    target.to_string(),
                    fstype.map(str::to_owned),
                    flags,
                ));
                Ok::<(), std::io::Error>(())
            },
        )
        .expect("shadow mount setup should succeed");

        let (source, target, fstype, flags) = call.expect("mount callback should be called");
        assert_eq!(source.as_deref(), Some("tmpfs"));
        assert_eq!(fstype.as_deref(), Some("tmpfs"));
        assert_eq!(flags, MsFlags::empty());
        assert!(
            target.starts_with("/proc/self/fd/"),
            "shadow mount target should be fd-anchored, got '{target}'"
        );
        assert_ne!(
            target, base_path,
            "shadow mount target should not use the raw path string"
        );
    }

    #[test]
    fn test_mount_shadow_fd_rejects_path_swap_before_mount() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let base_path = dir.path().join("target");
        let moved_path = dir.path().join("target.moved");
        let attacker_path = dir.path().join("target.attacker");
        std::fs::write(&base_path, b"ORIGINAL").expect("write base path");
        std::fs::write(&attacker_path, b"ATTACKER").expect("write attacker path");

        let base_path = base_path.to_string_lossy().to_string();
        let moved_path = moved_path.to_string_lossy().to_string();
        let attacker_path = attacker_path.to_string_lossy().to_string();

        let fd = safe_traverse(&base_path, false).expect("safe_traverse");
        std::fs::rename(&base_path, &moved_path).expect("rename base->moved");
        std::fs::rename(&attacker_path, &base_path).expect("rename attacker->base");

        let err = mount_shadow_fd(fd.as_raw_fd(), &base_path)
            .expect_err("mount_shadow_fd should fail closed after path swap");
        assert!(
            err.to_string()
                .contains("does not match the expected file descriptor")
                || err.to_string().contains("changed after verification")
                || err.to_string().contains("symlink detected"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_pin_validated_path_argument_rejects_path_swap_before_mount() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let base_path = dir.path().join("target.txt");
        let moved_path = dir.path().join("target.moved.txt");
        let attacker_path = dir.path().join("target.attacker.txt");
        std::fs::write(&base_path, b"ORIGINAL").expect("write base path");
        std::fs::write(&attacker_path, b"ATTACKER").expect("write attacker path");

        let base_path = base_path.to_string_lossy().to_string();
        let moved_path = moved_path.to_string_lossy().to_string();
        let attacker_path = attacker_path.to_string_lossy().to_string();

        let fd = safe_traverse(&base_path, false).expect("safe_traverse");
        let mut calls = 0usize;
        let result = pin_validated_path_argument_with(
            fd.as_raw_fd(),
            &base_path,
            |path| {
                assert_eq!(path, base_path.as_str());
                std::fs::rename(&base_path, &moved_path).map_err(|e| {
                    secure_sudoers_common::error::Error::IoContext(
                        "rename base->moved failed".to_string(),
                        e,
                    )
                })?;
                std::fs::rename(&attacker_path, &base_path).map_err(|e| {
                    secure_sudoers_common::error::Error::IoContext(
                        "rename attacker->base failed".to_string(),
                        e,
                    )
                })?;
                Ok(())
            },
            |_source, _target, _fstype, _flags| {
                calls += 1;
                Ok::<(), std::io::Error>(())
            },
        );

        let err = result.expect_err("path pinning should fail closed after path swap");
        assert!(
            err.to_string()
                .contains("does not match the expected file descriptor")
                || err
                    .to_string()
                    .contains("no longer matches the validated argument")
                || err.to_string().contains("symlink detected"),
            "unexpected error: {err}"
        );
        assert_eq!(calls, 0, "mount should not be attempted after path swap");
    }

    #[test]
    fn test_pin_validated_path_argument_uses_fd_anchored_mount_paths() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let base_path = dir.path().join("target.txt");
        std::fs::write(&base_path, b"ORIGINAL").expect("write base path");

        let base_path = base_path.to_string_lossy().to_string();
        let fd = safe_traverse(&base_path, false).expect("safe_traverse");
        let mut calls = Vec::<(Option<String>, String, String, MsFlags)>::new();

        pin_validated_path_argument_with(
            fd.as_raw_fd(),
            &base_path,
            |_| Ok(()),
            |source, target, _fstype, flags| {
                let resolved_target = std::fs::read_link(target)
                    .expect("target fd path should resolve while pinning")
                    .to_string_lossy()
                    .to_string();
                calls.push((
                    source.map(str::to_owned),
                    target.to_string(),
                    resolved_target,
                    flags,
                ));
                Ok::<(), std::io::Error>(())
            },
        )
        .expect("path pinning setup should succeed");

        assert_eq!(
            calls.len(),
            1,
            "path-only pinning helper should install one file self-bind mountpoint"
        );
        let (source, target, resolved_target, flags) = &calls[0];
        let source = source.as_deref().expect("bind source should be provided");
        assert!(
            source.starts_with("/proc/self/fd/"),
            "bind source should be fd-anchored, got '{source}'"
        );
        assert!(
            target.starts_with("/proc/self/fd/"),
            "bind target should be fd-anchored, got '{target}'"
        );
        assert_ne!(
            target, &base_path,
            "bind target should not use the raw path string"
        );
        assert_eq!(
            resolved_target, &base_path,
            "file pinning mount target should resolve to the validated file path"
        );
        assert_eq!(*flags, MsFlags::MS_BIND);
        assert_eq!(
            source, target,
            "pinning uses self-bind on fd-anchored mountpoints"
        );
    }

    #[test]
    fn test_pin_validated_path_argument_root_skips_parent_lock() {
        let root_path = "/".to_string();
        let fd = safe_traverse(&root_path, false).expect("safe_traverse");
        let mut calls = Vec::<(Option<String>, String, String, MsFlags)>::new();

        pin_validated_path_argument_with(
            fd.as_raw_fd(),
            &root_path,
            |_| Ok(()),
            |source, target, _fstype, flags| {
                let resolved_target = std::fs::read_link(target)
                    .expect("target fd path should resolve while pinning")
                    .to_string_lossy()
                    .to_string();
                calls.push((
                    source.map(str::to_owned),
                    target.to_string(),
                    resolved_target,
                    flags,
                ));
                Ok::<(), std::io::Error>(())
            },
        )
        .expect("root path pinning should succeed");

        assert_eq!(
            calls.len(),
            1,
            "root path pinning should only install the file self-bind mount"
        );
        let (source, target, resolved_target, flags) = &calls[0];
        let source = source.as_deref().expect("bind source should be provided");
        assert!(
            source.starts_with("/proc/self/fd/"),
            "bind source should be fd-anchored, got '{source}'"
        );
        assert!(
            target.starts_with("/proc/self/fd/"),
            "bind target should be fd-anchored, got '{target}'"
        );
        assert_eq!(
            resolved_target, "/",
            "root path pinning should target the canonical root path"
        );
        assert_eq!(*flags, MsFlags::MS_BIND);
    }

    #[test]
    fn test_pin_validated_path_argument_keeps_original_path_stable_after_swap_attempt() {
        require_root!();

        let dir = tempfile::TempDir::new().expect("tempdir");
        let base = dir.path().to_string_lossy().to_string();
        let owned_dir = format!("{base}/owned");
        let evil_dir = format!("{base}/evil");
        std::fs::create_dir(&owned_dir).expect("create owned dir");
        std::fs::create_dir(&evil_dir).expect("create evil dir");
        std::fs::write(format!("{owned_dir}/package.deb"), b"SAFE").expect("write safe payload");
        std::fs::write(format!("{evil_dir}/package.deb"), b"EVIL").expect("write evil payload");

        *GLOBAL_PATH.lock().unwrap() = Some(base.clone());

        fn child_fn() -> bool {
            let base = {
                let guard = GLOBAL_PATH.lock().unwrap();
                guard
                    .as_ref()
                    .expect("base path should be configured")
                    .clone()
            };
            let owned_dir = format!("{base}/owned");
            let owned_backup = format!("{base}/owned.backup");
            let evil_dir = format!("{base}/evil");
            let arg_path = format!("{owned_dir}/package.deb");

            if let Err(e) = setup_isolation(&mount_only_settings(), &[]) {
                eprintln!("setup_isolation failed: {e}");
                return false;
            }

            let validated = match check_path(&arg_path, &ValidationContext::Positional, &[]) {
                Ok(path) => path,
                Err(e) => {
                    eprintln!("check_path failed: {e}");
                    return false;
                }
            };
            if let Err(e) = pin_parent_chain_for_path(&validated.path) {
                eprintln!("pin_parent_chain_for_path failed: {e}");
                return false;
            }
            if let Err(e) = pin_path_at_fd(validated.fd.as_raw_fd(), &validated.path) {
                eprintln!("pin_path_at_fd failed: {e}");
                return false;
            }

            match std::fs::rename(&owned_dir, &owned_backup) {
                Ok(()) => {
                    if let Err(e) = std::os::unix::fs::symlink(&evil_dir, &owned_dir) {
                        eprintln!("symlink swap failed: {e}");
                        return false;
                    }
                }
                Err(e) => {
                    if e.raw_os_error() != Some(libc::EBUSY) {
                        eprintln!("unexpected rename failure after pin mount: {e}");
                        return false;
                    }
                }
            }

            match std::fs::read_to_string(&arg_path) {
                Ok(contents) => contents == "SAFE",
                Err(e) => {
                    eprintln!("failed reading pinned path: {e}");
                    false
                }
            }
        }

        let ok = unsafe { in_fork(child_fn) };
        assert!(
            ok,
            "path pinning should keep original argument path bound to validated content"
        );
    }

    #[test]
    fn test_pin_validated_path_argument_mountpoint_is_visible_at_argument_path() {
        require_root!();

        let dir = tempfile::TempDir::new().expect("tempdir");
        let arg_path = dir.path().join("package.deb");
        std::fs::write(&arg_path, b"SAFE").expect("write payload");
        let arg_path = arg_path.to_string_lossy().to_string();

        *GLOBAL_PATH.lock().unwrap() = Some(arg_path.clone());

        fn child_fn() -> bool {
            let arg_path = {
                let guard = GLOBAL_PATH.lock().unwrap();
                guard
                    .as_ref()
                    .expect("argument path should be configured")
                    .clone()
            };

            if let Err(e) = setup_isolation(&mount_only_settings(), &[]) {
                eprintln!("setup_isolation failed: {e}");
                return false;
            }

            let validated = match check_path(&arg_path, &ValidationContext::Positional, &[]) {
                Ok(path) => path,
                Err(e) => {
                    eprintln!("check_path failed: {e}");
                    return false;
                }
            };
            if let Err(e) = pin_parent_chain_for_path(&validated.path) {
                eprintln!("pin_parent_chain_for_path failed: {e}");
                return false;
            }
            if let Err(e) = pin_path_at_fd(validated.fd.as_raw_fd(), &validated.path) {
                eprintln!("pin_path_at_fd failed: {e}");
                return false;
            }

            let mountinfo = match std::fs::read_to_string("/proc/self/mountinfo") {
                Ok(content) => content,
                Err(e) => {
                    eprintln!("failed to read mountinfo: {e}");
                    return false;
                }
            };

            mountinfo
                .lines()
                .filter_map(|line| line.split_whitespace().nth(4))
                .any(|mountpoint| mountpoint == arg_path)
        }

        let ok = unsafe { in_fork(child_fn) };
        assert!(
            ok,
            "pinning should install a mountpoint at the validated argument path"
        );
    }

    #[test]
    fn test_split_parent_and_file_pinning_targets_expected_paths() {
        require_root!();

        let dir = tempfile::TempDir::new().expect("tempdir");
        let base = dir.path().to_string_lossy().to_string();
        let parent_path = format!("{base}/owned");
        let arg_path = format!("{parent_path}/payload.txt");
        std::fs::create_dir(&parent_path).expect("create parent dir");
        std::fs::write(&arg_path, b"SAFE").expect("write payload");

        *GLOBAL_PATH.lock().unwrap() = Some(base.clone());

        fn child_fn() -> bool {
            let base = {
                let guard = GLOBAL_PATH.lock().unwrap();
                guard
                    .as_ref()
                    .expect("base path should be configured")
                    .clone()
            };
            let parent_path = format!("{base}/owned");
            let arg_path = format!("{parent_path}/payload.txt");

            if let Err(e) = setup_isolation(&mount_only_settings(), &[]) {
                eprintln!("setup_isolation failed: {e}");
                return false;
            }

            let validated = match check_path(&arg_path, &ValidationContext::Positional, &[]) {
                Ok(path) => path,
                Err(e) => {
                    eprintln!("check_path failed: {e}");
                    return false;
                }
            };
            if let Err(e) = pin_parent_chain_for_path(&validated.path) {
                eprintln!("pin_parent_chain_for_path failed: {e}");
                return false;
            }
            if let Err(e) = pin_path_at_fd(validated.fd.as_raw_fd(), &validated.path) {
                eprintln!("pin_path_at_fd failed: {e}");
                return false;
            }

            let mountinfo = match std::fs::read_to_string("/proc/self/mountinfo") {
                Ok(content) => content,
                Err(e) => {
                    eprintln!("failed to read mountinfo: {e}");
                    return false;
                }
            };

            let mut saw_parent = false;
            let mut saw_file = false;
            for mountpoint in mountinfo
                .lines()
                .filter_map(|line| line.split_whitespace().nth(4))
            {
                if mountpoint == parent_path {
                    saw_parent = true;
                }
                if mountpoint == arg_path {
                    saw_file = true;
                }
            }
            saw_parent && saw_file
        }

        let ok = unsafe { in_fork(child_fn) };
        assert!(
            ok,
            "split parent/file pinning should lock the provided parent and the argument path"
        );
    }

    #[test]
    fn test_split_parent_and_file_pinning_blocks_grandparent_swap() {
        require_root!();

        let dir = tempfile::TempDir::new().expect("tempdir");
        let base = dir.path().to_string_lossy().to_string();
        let owned_dir = format!("{base}/owned");
        let owned_subdir = format!("{owned_dir}/sub");
        let evil_dir = format!("{base}/evil");
        let evil_subdir = format!("{evil_dir}/sub");
        let arg_path = format!("{owned_subdir}/payload.txt");
        std::fs::create_dir(&owned_dir).expect("create owned dir");
        std::fs::create_dir(&evil_dir).expect("create evil dir");
        std::fs::create_dir(&owned_subdir).expect("create owned subdir");
        std::fs::create_dir(&evil_subdir).expect("create evil subdir");
        std::fs::write(&arg_path, b"SAFE").expect("write safe payload");
        std::fs::write(format!("{evil_subdir}/payload.txt"), b"EVIL").expect("write evil payload");

        *GLOBAL_PATH.lock().unwrap() = Some(base.clone());

        fn child_fn() -> bool {
            let base = {
                let guard = GLOBAL_PATH.lock().unwrap();
                guard
                    .as_ref()
                    .expect("base path should be configured")
                    .clone()
            };
            let owned_dir = format!("{base}/owned");
            let owned_backup = format!("{base}/owned.backup");
            let evil_dir = format!("{base}/evil");
            let arg_path = format!("{base}/owned/sub/payload.txt");

            if let Err(e) = setup_isolation(&mount_only_settings(), &[]) {
                eprintln!("setup_isolation failed: {e}");
                return false;
            }

            let validated = match check_path(&arg_path, &ValidationContext::Positional, &[]) {
                Ok(path) => path,
                Err(e) => {
                    eprintln!("check_path failed: {e}");
                    return false;
                }
            };
            if let Err(e) = pin_parent_chain_for_path(&validated.path) {
                eprintln!("pin_parent_chain_for_path failed: {e}");
                return false;
            }
            if let Err(e) = pin_path_at_fd(validated.fd.as_raw_fd(), &validated.path) {
                eprintln!("pin_path_at_fd failed: {e}");
                return false;
            }

            match std::fs::rename(&owned_dir, &owned_backup) {
                Ok(()) => {
                    if let Err(e) = std::os::unix::fs::symlink(&evil_dir, &owned_dir) {
                        eprintln!("symlink swap failed: {e}");
                        return false;
                    }
                }
                Err(e) => {
                    if e.raw_os_error() != Some(libc::EBUSY) {
                        eprintln!("unexpected rename failure after split pinning: {e}");
                        return false;
                    }
                }
            }

            match std::fs::read_to_string(&arg_path) {
                Ok(contents) => contents == "SAFE",
                Err(e) => {
                    eprintln!("failed reading pinned path: {e}");
                    false
                }
            }
        }

        let ok = unsafe { in_fork(child_fn) };
        assert!(
            ok,
            "ancestor-chain + file pinning should keep original argument path stable"
        );
    }
}
