use super::config::InstallPaths;
use secure_sudoers_common::models::is_valid_tool_name;

pub(super) fn managed_targets(paths: &InstallPaths<'_>, tools: &[String]) -> Vec<String> {
    let mut targets: Vec<String> = vec![
        paths.binary.to_string(),
        paths.utils_binary.to_string(),
        paths.policy_path.to_string(),
        paths.public_key_path.to_string(),
        format!("{}.sig", paths.policy_path),
        paths.sudoers_path.to_string(),
    ];
    let entry_point_dir = std::path::Path::new(paths.entry_point_dir);
    targets.extend(
        tools
            .iter()
            .map(|tool| entry_point_dir.join(tool).to_string_lossy().into_owned()),
    );
    targets.sort_unstable();
    targets.dedup();
    targets
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FileIdentity {
    dev: u64,
    ino: u64,
}

pub(super) fn file_identity_from_metadata(metadata: &std::fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;

    FileIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    }
}

pub(super) fn file_identity(path: &std::path::Path) -> Result<FileIdentity, std::io::Error> {
    let metadata = std::fs::metadata(path)?;
    Ok(file_identity_from_metadata(&metadata))
}

pub(super) fn discover_managed_tools(binary: &str, entry_point_dir: &str) -> Vec<String> {
    let expected_identity = match file_identity(std::path::Path::new(binary)) {
        Ok(identity) => identity,
        Err(e) => {
            eprintln!(
                "Warning: cannot stat managed binary {binary} while discovering managed entries: {e}"
            );
            return Vec::new();
        }
    };
    let mut tools = Vec::new();
    let entries = match std::fs::read_dir(entry_point_dir) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!(
                "Warning: cannot scan entry-point directory {entry_point_dir} while unlocking fallback paths: {e}"
            );
            return tools;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                eprintln!("Warning: cannot read an entry from {entry_point_dir}: {e}");
                continue;
            }
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(e) => {
                eprintln!(
                    "Warning: cannot inspect file type for {}: {e}",
                    entry.path().display()
                );
                continue;
            }
        };
        if !file_type.is_file() {
            continue;
        }

        let link_path = entry.path();
        let is_managed_entry = match file_identity(&link_path) {
            Ok(identity) => identity == expected_identity,
            Err(e) => {
                eprintln!(
                    "Warning: cannot inspect file identity for {}: {e}",
                    link_path.display()
                );
                false
            }
        };
        if !is_managed_entry {
            continue;
        }

        let Some(tool_name) = link_path.file_name().and_then(|name| name.to_str()) else {
            eprintln!(
                "Warning: skipping managed entry with non-UTF8 name: {}",
                link_path.display()
            );
            continue;
        };
        if !is_valid_tool_name(tool_name) {
            eprintln!("Warning: skipping invalid managed entry name '{tool_name}'");
            continue;
        }
        tools.push(tool_name.to_string());
    }

    tools.sort_unstable();
    tools.dedup();
    tools
}
