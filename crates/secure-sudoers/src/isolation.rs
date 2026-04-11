pub(crate) mod capabilities;
mod mounts;
mod path_guard;

use secure_sudoers_common::error::Error;
use secure_sudoers_common::models::IsolationSettings;

#[cfg(test)]
use capabilities::{drop_bounding_capabilities_with, drop_capabilities, parse_cap_last_cap};
#[cfg(test)]
use mounts::{apply_private_mounts_with, apply_readonly_mounts_with, mount_shadow_fd};
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::require_root;
    use crate::testing::in_fork;
    use secure_sudoers_common::models::IsolationSettings;

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
            err.to_string().contains("changed after verification")
                || err.to_string().contains("symlink detected"),
            "unexpected error: {err}"
        );
        assert_eq!(calls, 0, "mount should not be attempted after path swap");
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
            err.to_string().contains("changed after verification")
                || err.to_string().contains("symlink detected"),
            "unexpected error: {err}"
        );
        assert_eq!(calls, 0, "mount should not be attempted after path swap");
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
            err.to_string().contains("changed after verification")
                || err.to_string().contains("symlink detected"),
            "unexpected error: {err}"
        );
    }
}
