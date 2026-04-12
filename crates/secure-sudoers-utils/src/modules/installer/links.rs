use crate::modules::path_security::{secure_directory, secure_parent_directory};
use secure_sudoers_common::models::is_valid_tool_name;
use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub(super) fn install_tool_links_to(
    tools: &[String],
    binary: &str,
    entry_point_dir: &str,
) -> (Vec<String>, Vec<String>) {
    let mut successful = Vec::new();
    let mut errors = Vec::new();
    let binary_path = Path::new(binary);
    let secure_binary_parent =
        match secure_parent_directory(binary_path, "managed binary parent directory") {
            Ok(secure_parent) => secure_parent,
            Err(e) => {
                errors.push(format!(
                    "Cannot securely resolve managed binary {binary}: {e}"
                ));
                return (successful, errors);
            }
        };
    let binary_name = match binary_path.file_name() {
        Some(name) => name,
        None => {
            errors.push(format!(
                "Cannot determine managed binary name from path {binary}"
            ));
            return (successful, errors);
        }
    };
    let binary_name_c = match CString::new(binary_name.as_bytes()) {
        Ok(name) => name,
        Err(_) => {
            errors.push(format!(
                "Managed binary path contains interior NUL byte: {binary}"
            ));
            return (successful, errors);
        }
    };
    let binary_stat = match stat_component(secure_binary_parent.fd.as_raw_fd(), &binary_name_c) {
        Ok(stat) => stat,
        Err(e) => {
            errors.push(format!("Cannot stat managed binary {binary}: {e}"));
            return (successful, errors);
        }
    };
    if (binary_stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
        errors.push(format!("Managed binary {binary} is not a regular file"));
        return (successful, errors);
    }
    let expected_identity = stat_identity(&binary_stat);

    let entry_dir_path = Path::new(entry_point_dir);
    let secure_entry_dir = match secure_directory(entry_dir_path, "entry-point directory") {
        Ok(secure_dir) => secure_dir,
        Err(e) => {
            errors.push(format!(
                "Cannot securely resolve entry-point directory {entry_point_dir}: {e}"
            ));
            return (successful, errors);
        }
    };
    let entry_dir_fd = secure_entry_dir.fd.as_raw_fd();

    for tool in tools {
        if !is_valid_tool_name(tool) {
            errors.push(format!("Invalid tool name '{tool}'"));
            continue;
        }
        let link_name_c = match CString::new(tool.as_str()) {
            Ok(name) => name,
            Err(_) => {
                errors.push(format!(
                    "Invalid tool name '{tool}': contains interior NUL byte"
                ));
                continue;
            }
        };
        let link_path = entry_dir_path.join(tool);
        let mut skip = false;
        match stat_component(entry_dir_fd, &link_name_c) {
            Ok(stat) => {
                if (stat.st_mode & libc::S_IFMT) == libc::S_IFLNK {
                    if let Err(e) = unlink_component(entry_dir_fd, &link_name_c) {
                        errors.push(format!(
                            "Cannot remove old symlink {}: {e}",
                            link_path.display()
                        ));
                        skip = true;
                    }
                } else if (stat.st_mode & libc::S_IFMT) == libc::S_IFREG {
                    if stat_identity(&stat) == expected_identity {
                        println!(
                            "  Entry point {} already linked to {binary}",
                            link_path.display()
                        );
                        successful.push(tool.clone());
                        continue;
                    }
                    let backup_name = format!("{tool}.bak");
                    let backup_name_c = match CString::new(backup_name.as_str()) {
                        Ok(name) => name,
                        Err(_) => {
                            errors.push(format!(
                                "Cannot create backup name for {}: contains interior NUL byte",
                                link_path.display()
                            ));
                            continue;
                        }
                    };
                    if let Err(e) = rename_component(entry_dir_fd, &link_name_c, &backup_name_c) {
                        errors.push(format!("Cannot back up {}: {e}", link_path.display()));
                        skip = true;
                    } else {
                        let backup_path = entry_dir_path.join(&backup_name);
                        println!(
                            "  Backed up {} -> {}",
                            link_path.display(),
                            backup_path.display()
                        );
                    }
                } else {
                    errors.push(format!(
                        "Skipping {}: not a regular file or symlink",
                        link_path.display()
                    ));
                    skip = true;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                errors.push(format!("Cannot stat {}: {e}", link_path.display()));
                skip = true;
            }
        }
        if skip {
            continue;
        }

        match hard_link_component(
            secure_binary_parent.fd.as_raw_fd(),
            &binary_name_c,
            entry_dir_fd,
            &link_name_c,
        ) {
            Ok(()) => {
                println!("  Linked {} to {binary}", link_path.display());
                successful.push(tool.clone());
            }
            Err(e) => {
                let err_msg = if e.raw_os_error() == Some(libc::EXDEV) {
                    format!(
                        "Cannot create hard link {} to {binary}: filesystems differ (EXDEV). \
Place the managed binary and entry-point directory on the same filesystem.",
                        link_path.display()
                    )
                } else {
                    format!(
                        "Cannot create hard link {} to {binary}: {e}",
                        link_path.display()
                    )
                };
                errors.push(err_msg);
            }
        }
    }
    (successful, errors)
}

fn stat_component(dir_fd: i32, name: &CString) -> std::io::Result<libc::stat> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstatat(dir_fd, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) };
    if rc == 0 {
        return Ok(stat);
    }
    Err(std::io::Error::last_os_error())
}

fn unlink_component(dir_fd: i32, name: &CString) -> std::io::Result<()> {
    let rc = unsafe { libc::unlinkat(dir_fd, name.as_ptr(), 0) };
    if rc == 0 {
        return Ok(());
    }
    Err(std::io::Error::last_os_error())
}

fn rename_component(dir_fd: i32, from_name: &CString, to_name: &CString) -> std::io::Result<()> {
    let rc = unsafe { libc::renameat(dir_fd, from_name.as_ptr(), dir_fd, to_name.as_ptr()) };
    if rc == 0 {
        return Ok(());
    }
    Err(std::io::Error::last_os_error())
}

fn hard_link_component(
    source_dir_fd: i32,
    source_name: &CString,
    target_dir_fd: i32,
    target_name: &CString,
) -> std::io::Result<()> {
    let rc = unsafe {
        libc::linkat(
            source_dir_fd,
            source_name.as_ptr(),
            target_dir_fd,
            target_name.as_ptr(),
            0,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    Err(std::io::Error::last_os_error())
}

fn stat_identity(stat: &libc::stat) -> (u64, u64) {
    (stat.st_dev, stat.st_ino)
}
