use super::targets::{file_identity, file_identity_from_metadata};
use secure_sudoers_common::models::is_valid_tool_name;

pub(super) fn install_tool_links_to(
    tools: &[String],
    binary: &str,
    entry_point_dir: &str,
) -> (Vec<String>, Vec<String>) {
    let mut successful = Vec::new();
    let mut errors = Vec::new();
    let binary_path = std::path::Path::new(binary);
    let expected_identity = match file_identity(binary_path) {
        Ok(identity) => identity,
        Err(e) => {
            errors.push(format!("Cannot stat managed binary {binary}: {e}"));
            return (successful, errors);
        }
    };

    for tool in tools {
        if !is_valid_tool_name(tool) {
            errors.push(format!("Invalid tool name '{tool}'"));
            continue;
        }
        let link_path = std::path::Path::new(entry_point_dir).join(tool);
        let mut skip = false;
        match std::fs::symlink_metadata(&link_path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    if let Err(e) = std::fs::remove_file(&link_path) {
                        errors.push(format!(
                            "Cannot remove old symlink {}: {e}",
                            link_path.display()
                        ));
                        skip = true;
                    }
                } else if meta.file_type().is_file() {
                    if file_identity_from_metadata(&meta) == expected_identity {
                        println!(
                            "  Entry point {} already linked to {binary}",
                            link_path.display()
                        );
                        successful.push(tool.clone());
                        continue;
                    }
                    let backup = format!("{}.bak", link_path.display());
                    if let Err(e) = std::fs::rename(&link_path, &backup) {
                        errors.push(format!("Cannot back up {}: {e}", link_path.display()));
                        skip = true;
                    } else {
                        println!("  Backed up {} -> {backup}", link_path.display());
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

        match std::fs::hard_link(binary_path, &link_path) {
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
