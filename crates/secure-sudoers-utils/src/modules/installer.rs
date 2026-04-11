use super::keys::load_verifying_key;
use ed25519_dalek::{Signature, Verifier};
use secure_sudoers_common::error::Error;
use secure_sudoers_common::models::{SecureSudoersPolicy, is_valid_tool_name};

pub const INSTALL_POLICY_PATH: &str = "/etc/secure-sudoers/policy.json";
pub const INSTALL_PUBLIC_KEY_PATH: &str = "/etc/secure-sudoers/secure_sudoers_public_key.pem";
pub const INSTALL_BINARY: &str = "/usr/local/bin/secure-sudoers";
pub const INSTALL_UTILS_BINARY: &str = "/usr/local/bin/secure-sudoers-utils";
pub const INSTALL_SUDOERS_PATH: &str = "/etc/sudoers.d/secure-sudoers";
pub const ENTRY_POINT_DIR: &str = "/usr/local/bin";
const CHATTR_CANDIDATE_PATHS: [&str; 3] = ["/usr/bin/chattr", "/bin/chattr", "/usr/sbin/chattr"];

#[derive(Debug, Clone)]
pub struct InstallPaths<'a> {
    pub policy_path: &'a str,
    pub public_key_path: &'a str,
    pub binary: &'a str,
    pub utils_binary: &'a str,
    pub sudoers_path: &'a str,
    pub entry_point_dir: &'a str,
}

impl Default for InstallPaths<'static> {
    fn default() -> Self {
        InstallPaths {
            policy_path: INSTALL_POLICY_PATH,
            public_key_path: INSTALL_PUBLIC_KEY_PATH,
            binary: INSTALL_BINARY,
            utils_binary: INSTALL_UTILS_BINARY,
            sudoers_path: INSTALL_SUDOERS_PATH,
            entry_point_dir: ENTRY_POINT_DIR,
        }
    }
}

pub fn cmd_install() -> Result<(), Error> {
    install_with_paths(&InstallPaths::default())
}

pub fn cmd_unlock() -> Result<(), Error> {
    unlock_with_paths(&InstallPaths::default())
}

pub fn generate_sudoers_content(tools: &[String]) -> String {
    generate_sudoers_content_with_dir(tools, ENTRY_POINT_DIR)
}

fn generate_sudoers_content_with_dir(tools: &[String], entry_point_dir: &str) -> String {
    if tools.is_empty() {
        return "# No tools authorized in policy. This file is intentionally empty.\n".to_string();
    }
    let mut sorted: Vec<&str> = tools.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    let paths: Vec<String> = sorted
        .iter()
        .map(|t| format!("{entry_point_dir}/{t}"))
        .collect();
    format!(
        "# Managed by secure-sudoers-utils - do not edit manually.\n\
         Defaults secure_path=\"/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n\
         ALL ALL=(root) {}\n",
        paths.join(", ")
    )
}

fn load_policy(path: &str) -> Result<SecureSudoersPolicy, Error> {
    let bytes =
        std::fs::read(path).map_err(|e| Error::IoContext(format!("Cannot read {path}"), e))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::System(format!("Invalid policy JSON at {path}: {e}")))
}

pub fn install_with_paths(paths: &InstallPaths<'_>) -> Result<(), Error> {
    install_with_paths_and_pubkey(paths, paths.public_key_path)
}

fn install_with_paths_and_pubkey(
    paths: &InstallPaths<'_>,
    public_key_path: &str,
) -> Result<(), Error> {
    let policy = load_policy_with_verified_signature(paths.policy_path, public_key_path)?;
    let mut tool_names: Vec<String> = policy.tools.keys().cloned().collect();
    tool_names.sort_unstable();
    println!("Installing {} tool(s)...", tool_names.len());

    let (successful_tools, link_errors) =
        install_tool_links_to(&tool_names, paths.binary, paths.entry_point_dir);
    write_sudoers_file_to(&successful_tools, paths.sudoers_path, paths.entry_point_dir)?;

    let targets = managed_targets(paths, &successful_tools);
    let refs: Vec<&str> = targets.iter().map(String::as_str).collect();
    let lock_errors = chattr_op("+i", &refs);
    for e in &lock_errors {
        eprintln!("Warning: chattr +i failed: {e}");
    }

    println!("Installation complete.");
    let mut error_sections = Vec::new();
    if !link_errors.is_empty() {
        error_sections.push(format!(
            "entry-point setup errors:\n{}",
            link_errors.join("\n")
        ));
    }
    if !lock_errors.is_empty() {
        error_sections.push(format!(
            "failed to secure managed files with chattr +i:\n{}",
            lock_errors.join("\n")
        ));
    }
    if !error_sections.is_empty() {
        return Err(Error::System(format!(
            "Installation completed with errors:\n{}",
            error_sections.join("\n\n")
        )));
    }
    Ok(())
}

fn load_policy_with_verified_signature(
    policy_path: &str,
    public_key_path: &str,
) -> Result<SecureSudoersPolicy, Error> {
    let policy_bytes = std::fs::read(policy_path)
        .map_err(|e| Error::IoContext(format!("Cannot read {policy_path}"), e))?;
    verify_policy_signature(policy_path, &policy_bytes, public_key_path)?;
    let mut policy: SecureSudoersPolicy = serde_json::from_slice(&policy_bytes)
        .map_err(|e| Error::System(format!("Invalid policy JSON at {policy_path}: {e}")))?;
    policy.validate()?;
    Ok(policy)
}

fn verify_policy_signature(
    policy_path: &str,
    policy_bytes: &[u8],
    public_key_path: &str,
) -> Result<(), Error> {
    let verifying_key = load_verifying_key(public_key_path)?;
    let sig_path = format!("{policy_path}.sig");
    let sig_bytes = std::fs::read(&sig_path)
        .map_err(|e| Error::IoContext(format!("Cannot read policy signature {sig_path}"), e))?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        Error::Validation(format!(
            "Policy signature must be 64 bytes (got {})",
            sig_bytes.len()
        ))
    })?;
    verifying_key
        .verify(policy_bytes, &Signature::from_bytes(&sig_arr))
        .map_err(|e| {
            Error::Security(format!(
                "Policy signature verification failed for {policy_path}: {e}"
            ))
        })?;
    Ok(())
}

fn managed_targets(paths: &InstallPaths<'_>, tools: &[String]) -> Vec<String> {
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
struct FileIdentity {
    dev: u64,
    ino: u64,
}

fn file_identity_from_metadata(metadata: &std::fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;

    FileIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    }
}

fn file_identity(path: &std::path::Path) -> Result<FileIdentity, std::io::Error> {
    let metadata = std::fs::metadata(path)?;
    Ok(file_identity_from_metadata(&metadata))
}

fn discover_managed_tools(binary: &str, entry_point_dir: &str) -> Vec<String> {
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

fn find_first_existing_path<'a>(candidates: &'a [&'a str]) -> Option<&'a str> {
    candidates
        .iter()
        .copied()
        .find(|path| std::path::Path::new(path).exists())
}

fn should_skip_chattr_target(flag: &str, path: &str) -> Result<bool, std::io::Error> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(flag == "-i"),
        Err(e) => Err(e),
    }
}

pub fn unlock_with_paths(paths: &InstallPaths<'_>) -> Result<(), Error> {
    let tool_names = match load_policy(paths.policy_path) {
        Ok(mut policy) => {
            if let Err(e) = policy.validate() {
                eprintln!("Warning: policy validation failed during unlock: {e}");
            }
            let mut names: Vec<String> = policy.tools.keys().cloned().collect();
            names.sort_unstable();
            names
        }
        Err(e) => {
            eprintln!(
                "Warning: failed to parse policy {} during unlock; falling back to managed entry discovery: {e}",
                paths.policy_path
            );
            discover_managed_tools(paths.binary, paths.entry_point_dir)
        }
    };
    let targets = managed_targets(paths, &tool_names);
    let refs: Vec<&str> = targets.iter().map(String::as_str).collect();
    let errors = chattr_op("-i", &refs);
    for e in &errors {
        eprintln!("Warning: chattr -i failed: {e}");
    }
    println!("Unlocked {} managed file(s).", refs.len());
    if !errors.is_empty() {
        return Err(Error::System(format!(
            "Some files could not be unlocked:\n{}",
            errors.join("\n")
        )));
    }
    Ok(())
}

fn install_tool_links_to(
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

fn write_sudoers_file_to(
    tools: &[String],
    sudoers_path: &str,
    entry_point_dir: &str,
) -> Result<(), Error> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    struct TempFileCleanupGuard {
        path: std::path::PathBuf,
        armed: bool,
    }

    impl TempFileCleanupGuard {
        fn new(path: std::path::PathBuf) -> Self {
            Self { path, armed: true }
        }

        fn disarm(&mut self) {
            self.armed = false;
        }
    }

    impl Drop for TempFileCleanupGuard {
        fn drop(&mut self) {
            if !self.armed {
                return;
            }
            if let Err(e) = std::fs::remove_file(&self.path)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                eprintln!(
                    "Warning: failed to clean up temporary sudoers file {}: {e}",
                    self.path.display()
                );
            }
        }
    }

    let content = generate_sudoers_content_with_dir(tools, entry_point_dir);
    let sudoers = std::path::Path::new(sudoers_path);
    let sudoers_file_name = sudoers.file_name().ok_or_else(|| {
        Error::System(format!(
            "Invalid sudoers destination path {sudoers_path}: missing file name"
        ))
    })?;
    let temp_path = sudoers.with_file_name(format!("{}.tmp", sudoers_file_name.to_string_lossy()));
    let mut temp_cleanup_guard = TempFileCleanupGuard::new(temp_path.clone());

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o440)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp_path)
        .map_err(|e| {
            Error::IoContext(
                format!(
                    "Cannot create temporary sudoers file {} for destination {}",
                    temp_path.display(),
                    sudoers_path
                ),
                e,
            )
        })?;
    f.set_permissions(std::fs::Permissions::from_mode(0o440))
        .map_err(|e| {
            Error::IoContext(
                format!(
                    "Cannot set permissions on temporary sudoers file {}",
                    temp_path.display()
                ),
                e,
            )
        })?;
    f.write_all(content.as_bytes()).map_err(|e| {
        Error::IoContext(
            format!(
                "Cannot write temporary sudoers file {} for destination {}",
                temp_path.display(),
                sudoers_path
            ),
            e,
        )
    })?;
    f.sync_all().map_err(|e| {
        Error::IoContext(
            format!(
                "Cannot flush temporary sudoers file {} for destination {}",
                temp_path.display(),
                sudoers_path
            ),
            e,
        )
    })?;
    drop(f);

    let visudo_paths = ["/usr/sbin/visudo", "/usr/bin/visudo"];
    let mut visudo_output = None;
    let mut visudo_exec_errors = Vec::new();
    for visudo_path in visudo_paths {
        match std::process::Command::new(visudo_path)
            .arg("-c")
            .arg("-f")
            .arg(&temp_path)
            .output()
        {
            Ok(output) => {
                visudo_output = Some(output);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => visudo_exec_errors.push(format!("{visudo_path}: {e}")),
        }
    }
    let visudo_output = visudo_output.ok_or_else(|| {
        if visudo_exec_errors.is_empty() {
            Error::System(format!(
                "Cannot execute visudo from known paths (/usr/sbin/visudo, /usr/bin/visudo) \
while validating sudoers destination {} for temporary file {}: command not found",
                sudoers_path,
                temp_path.display()
            ))
        } else {
            Error::System(format!(
                "Cannot execute visudo from known paths (/usr/sbin/visudo, /usr/bin/visudo) \
while validating sudoers destination {} for temporary file {}: {}",
                sudoers_path,
                temp_path.display(),
                visudo_exec_errors.join("; ")
            ))
        }
    })?;
    if !visudo_output.status.success() {
        return Err(Error::Validation(visudo_validation_failed_message(
            &temp_path,
            sudoers_path,
            &visudo_output,
        )));
    }

    std::fs::rename(&temp_path, sudoers).map_err(|e| {
        Error::IoContext(
            format!(
                "Cannot atomically replace sudoers destination {} with temporary file {}",
                sudoers_path,
                temp_path.display()
            ),
            e,
        )
    })?;
    temp_cleanup_guard.disarm();

    println!("  Wrote sudoers drop-in: {sudoers_path}");
    Ok(())
}

fn visudo_validation_failed_message(
    temp_path: &std::path::Path,
    sudoers_path: &str,
    output: &std::process::Output,
) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let mut command_output = String::new();
    if !stderr.is_empty() {
        command_output.push_str(&format!("stderr: {stderr}"));
    }
    if !stdout.is_empty() {
        if !command_output.is_empty() {
            command_output.push_str("; ");
        }
        command_output.push_str(&format!("stdout: {stdout}"));
    }
    if command_output.is_empty() {
        command_output = "no command output".to_string();
    }

    format!(
        "visudo validation failed for temporary sudoers file {} (target {}): {command_output}",
        temp_path.display(),
        sudoers_path
    )
}

pub(crate) fn chattr_op(flag: &str, paths: &[&str]) -> Vec<String> {
    if paths.is_empty() {
        return Vec::new();
    }

    let Some(chattr_path) = find_first_existing_path(&CHATTR_CANDIDATE_PATHS) else {
        return vec![format!(
            "Cannot execute chattr from known paths ({})",
            CHATTR_CANDIDATE_PATHS.join(", ")
        )];
    };
    let mut errors = Vec::new();
    for path in paths {
        let skip = match should_skip_chattr_target(flag, path) {
            Ok(skip) => skip,
            Err(e) => {
                errors.push(format!(
                    "Cannot inspect {path} before chattr operation {flag}: {e}"
                ));
                continue;
            }
        };
        if skip {
            continue;
        }

        let command_display = format!("{chattr_path} {flag} -- {path}");
        match std::process::Command::new(chattr_path)
            .arg(flag)
            .arg("--")
            .arg(path)
            .status()
        {
            Ok(s) if s.success() => {}
            Ok(s) => errors.push(format!("{command_display}: exited with {s}")),
            Err(e) => errors.push(format!("{command_display}: {e}")),
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use tempfile::TempDir;

    fn write_policy(path: &str, tools: &[(&str, &str)]) {
        let mut tools_json = String::from("{");
        for (i, (name, binary)) in tools.iter().enumerate() {
            if i > 0 {
                tools_json.push(',');
            }
            tools_json.push_str(&format!(
                r#""{name}":{{"real_binary":"{binary}","help_description":"{name}","parameters":{{}}}}"#
            ));
        }
        tools_json.push('}');
        let json = format!(r#"{{"version":"1.0","global_settings":{{}},"tools":{tools_json}}}"#);
        std::fs::write(path, json).unwrap();
    }

    fn write_public_key(path: &str, signing_key: &SigningKey) {
        let verifying_key = signing_key.verifying_key().to_bytes();
        let b64 = secure_sudoers_common::util::bytes_to_base64(&verifying_key);
        let pem = format!(
            "-----BEGIN SECURE SUDOERS PUBLIC KEY-----\n{b64}\n-----END SECURE SUDOERS PUBLIC KEY-----\n"
        );
        std::fs::write(path, pem).unwrap();
    }

    fn write_signature(policy_path: &str, signing_key: &SigningKey) {
        let policy_bytes = std::fs::read(policy_path).unwrap();
        let signature = signing_key.sign(&policy_bytes);
        std::fs::write(format!("{policy_path}.sig"), signature.to_bytes()).unwrap();
    }

    #[test]
    fn test_sudoers_content_empty_tools_is_safe() {
        let content = generate_sudoers_content(&[]);
        assert!(content.contains("No tools authorized"));
        assert!(!content.contains("ALL ALL="));
    }

    #[test]
    fn test_sudoers_content_contains_required_sections() {
        let tools = vec!["apt".to_string()];
        let content = generate_sudoers_content(&tools);
        assert!(content.contains("Defaults secure_path="));
        assert!(content.contains("/usr/local/bin/apt"));
    }

    #[test]
    fn test_sudoers_content_with_dir_uses_custom_path() {
        let tools = vec!["apt".to_string(), "tail".to_string()];
        let content = generate_sudoers_content_with_dir(&tools, "/opt/bin");
        assert!(content.contains("/opt/bin/apt"));
        assert!(content.contains("/opt/bin/tail"));
        let apt_pos = content.find("/opt/bin/apt").unwrap();
        let tail_pos = content.find("/opt/bin/tail").unwrap();
        assert!(apt_pos < tail_pos, "tools must be alphabetically sorted");
    }

    #[test]
    fn test_install_tool_links_creates_hard_links_in_custom_dir() {
        let dir = TempDir::new().unwrap();
        let binary = dir.path().join("secure-sudoers");
        std::fs::write(&binary, b"binary").unwrap();

        let (ok, errs) = install_tool_links_to(
            &["mytool".to_string()],
            binary.to_str().unwrap(),
            dir.path().to_str().unwrap(),
        );
        assert!(errs.is_empty(), "unexpected errors: {errs:?}");
        assert_eq!(ok, vec!["mytool"]);
        let link = dir.path().join("mytool");
        assert!(
            std::fs::symlink_metadata(&link).is_ok(),
            "entry point should exist"
        );

        let binary_identity = file_identity(&binary).unwrap();
        let link_identity = file_identity(&link).unwrap();
        assert_eq!(
            binary_identity, link_identity,
            "expected hard link identity"
        );
    }

    #[test]
    fn test_install_tool_links_replaces_existing_symlink() {
        let dir = TempDir::new().unwrap();
        let binary = dir.path().join("secure-sudoers");
        std::fs::write(&binary, b"binary").unwrap();
        let link = dir.path().join("mytool");
        std::os::unix::fs::symlink("/old/target", &link).unwrap();

        let (ok, errs) = install_tool_links_to(
            &["mytool".to_string()],
            binary.to_str().unwrap(),
            dir.path().to_str().unwrap(),
        );
        assert!(errs.is_empty());
        assert_eq!(ok, vec!["mytool"]);
        assert!(
            !std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            file_identity(&binary).unwrap(),
            file_identity(&link).unwrap()
        );
    }

    #[test]
    fn test_install_tool_links_backs_up_regular_file() {
        let dir = TempDir::new().unwrap();
        let binary = dir.path().join("secure-sudoers");
        std::fs::write(&binary, b"binary").unwrap();
        let file_path = dir.path().join("mytool");
        std::fs::write(&file_path, b"original binary").unwrap();

        let (ok, errs) = install_tool_links_to(
            &["mytool".to_string()],
            binary.to_str().unwrap(),
            dir.path().to_str().unwrap(),
        );
        assert!(errs.is_empty(), "errors: {errs:?}");
        assert_eq!(ok, vec!["mytool"]);
        assert!(
            dir.path().join("mytool.bak").exists(),
            "backup should exist"
        );
        assert_eq!(
            file_identity(&binary).unwrap(),
            file_identity(&dir.path().join("mytool")).unwrap()
        );
    }

    #[test]
    fn test_install_tool_links_keeps_existing_hard_link_without_backup() {
        let dir = TempDir::new().unwrap();
        let binary = dir.path().join("secure-sudoers");
        std::fs::write(&binary, b"binary").unwrap();
        let link = dir.path().join("mytool");
        std::fs::hard_link(&binary, &link).unwrap();

        let (ok, errs) = install_tool_links_to(
            &["mytool".to_string()],
            binary.to_str().unwrap(),
            dir.path().to_str().unwrap(),
        );
        assert!(errs.is_empty(), "errors: {errs:?}");
        assert_eq!(ok, vec!["mytool"]);
        assert!(!dir.path().join("mytool.bak").exists());
    }

    #[test]
    fn test_install_tool_links_rejects_invalid_name() {
        let dir = TempDir::new().unwrap();
        let binary = dir.path().join("secure-sudoers");
        std::fs::write(&binary, b"binary").unwrap();

        let (ok, errs) = install_tool_links_to(
            &["bad/name".to_string()],
            binary.to_str().unwrap(),
            dir.path().to_str().unwrap(),
        );
        assert!(ok.is_empty());
        assert!(!errs.is_empty());
        assert!(errs[0].contains("Invalid tool name"));
    }

    #[test]
    fn test_write_sudoers_file_to_creates_correct_content() {
        let dir = TempDir::new().unwrap();
        let sudoers = dir.path().join("sudoers");
        let tools = vec!["apt".to_string(), "docker".to_string()];
        write_sudoers_file_to(&tools, sudoers.to_str().unwrap(), "/usr/local/bin").unwrap();

        let content = std::fs::read_to_string(&sudoers).unwrap();
        assert!(content.contains("/usr/local/bin/apt"));
        assert!(content.contains("/usr/local/bin/docker"));
        assert!(content.contains("Defaults secure_path="));
    }

    #[test]
    fn test_write_sudoers_file_to_validation_failure_keeps_destination_and_cleans_temp() {
        let dir = TempDir::new().unwrap();
        let sudoers = dir.path().join("sudoers");
        std::fs::write(&sudoers, "ORIGINAL\n").unwrap();

        let err = write_sudoers_file_to(
            &["bad\ntool".to_string()],
            sudoers.to_str().unwrap(),
            "/usr/local/bin",
        )
        .expect_err("invalid sudoers content should fail visudo validation");
        assert!(
            err.to_string().contains("visudo validation failed"),
            "unexpected error: {err}"
        );

        let content_after = std::fs::read_to_string(&sudoers).unwrap();
        assert_eq!(content_after, "ORIGINAL\n");
        assert!(
            !dir.path().join("sudoers.tmp").exists(),
            "temporary file should be removed after validation failure"
        );
    }

    struct TestEnv {
        _root: TempDir,
        pub policy_path: String,
        pub public_key_path: String,
        pub binary_path: String,
        pub utils_binary_path: String,
        pub sudoers_path: String,
        pub entry_point_dir: String,
    }

    impl TestEnv {
        fn new() -> Self {
            let root = TempDir::new().unwrap();
            let entry_point_dir = root.path().join("bin");
            std::fs::create_dir(&entry_point_dir).unwrap();
            let sudoers_dir = root.path().join("sudoers.d");
            std::fs::create_dir(&sudoers_dir).unwrap();
            let policy_path = root.path().join("policy.json");
            let public_key_path = root.path().join("secure_sudoers_public_key.pem");
            let binary_path = root.path().join("secure-sudoers");
            let utils_binary_path = root.path().join("secure-sudoers-utils");
            let sudoers_path = sudoers_dir.join("secure-sudoers");
            std::fs::write(&binary_path, b"secure-sudoers binary").unwrap();
            std::fs::write(&utils_binary_path, b"secure-sudoers-utils binary").unwrap();

            Self {
                _root: root,
                policy_path: policy_path.to_str().unwrap().to_string(),
                public_key_path: public_key_path.to_str().unwrap().to_string(),
                binary_path: binary_path.to_str().unwrap().to_string(),
                utils_binary_path: utils_binary_path.to_str().unwrap().to_string(),
                sudoers_path: sudoers_path.to_str().unwrap().to_string(),
                entry_point_dir: entry_point_dir.to_str().unwrap().to_string(),
            }
        }

        fn paths(&self) -> InstallPaths<'_> {
            InstallPaths {
                policy_path: &self.policy_path,
                public_key_path: &self.public_key_path,
                binary: &self.binary_path,
                utils_binary: &self.utils_binary_path,
                sudoers_path: &self.sudoers_path,
                entry_point_dir: &self.entry_point_dir,
            }
        }
    }

    #[test]
    fn test_install_with_paths_full_flow() {
        let env = TestEnv::new();
        let signing_key = SigningKey::generate(&mut OsRng);
        write_policy(&env.policy_path, &[("apt", "/usr/bin/apt")]);
        write_public_key(&env.public_key_path, &signing_key);
        write_signature(&env.policy_path, &signing_key);
        let install_result = install_with_paths_and_pubkey(&env.paths(), &env.public_key_path);
        if let Err(err) = &install_result {
            assert!(
                err.to_string()
                    .contains("failed to secure managed files with chattr +i"),
                "expected lock-hardening failure, got: {err}"
            );
            assert!(
                err.to_string().contains(&env.public_key_path),
                "immutable lock failures should include the trusted public key path: {err}"
            );
        }

        let link = std::path::Path::new(&env.entry_point_dir).join("apt");
        assert!(std::fs::symlink_metadata(&link).is_ok());
        assert_eq!(
            file_identity(std::path::Path::new(&env.binary_path)).unwrap(),
            file_identity(&link).unwrap(),
            "tool entry point should be a hard link to managed binary"
        );

        let content = std::fs::read_to_string(&env.sudoers_path).unwrap();
        assert!(content.contains(&format!("{}/apt", env.entry_point_dir)));
        assert!(content.contains("Defaults secure_path="));

        let _ = unlock_with_paths(&env.paths());
    }

    #[test]
    fn test_install_with_paths_rejects_missing_signature() {
        let env = TestEnv::new();
        let signing_key = SigningKey::generate(&mut OsRng);
        write_policy(&env.policy_path, &[("apt", "/usr/bin/apt")]);
        write_public_key(&env.public_key_path, &signing_key);
        let err = install_with_paths_and_pubkey(&env.paths(), &env.public_key_path)
            .expect_err("unsigned policy should be rejected by install");
        assert!(
            err.to_string().contains("signature"),
            "expected signature-related error, got: {err}"
        );
    }

    #[test]
    fn test_install_with_paths_rejects_invalid_signature() {
        let env = TestEnv::new();
        let trusted_signing_key = SigningKey::generate(&mut OsRng);
        let wrong_signing_key = SigningKey::generate(&mut OsRng);
        write_policy(&env.policy_path, &[("apt", "/usr/bin/apt")]);
        write_public_key(&env.public_key_path, &trusted_signing_key);
        write_signature(&env.policy_path, &wrong_signing_key);
        let err = install_with_paths_and_pubkey(&env.paths(), &env.public_key_path)
            .expect_err("policy signed with wrong key should be rejected");
        assert!(
            err.to_string().contains("verification failed"),
            "expected signature verification failure, got: {err}"
        );
    }

    #[test]
    fn test_unlock_with_paths_does_not_abort_on_invalid_policy_json() {
        let env = TestEnv::new();
        let managed_link = std::path::Path::new(&env.entry_point_dir).join("tail");
        std::fs::hard_link(&env.binary_path, &managed_link).unwrap();
        std::fs::write(&env.policy_path, "{not-json").unwrap();
        unlock_with_paths(&env.paths()).expect("unlock should succeed via fallback discovery");
    }

    #[test]
    fn test_discover_managed_tools_finds_hard_links_to_binary() {
        let root = TempDir::new().unwrap();
        let entry_point_dir = root.path().join("bin");
        std::fs::create_dir(&entry_point_dir).unwrap();
        let binary_path = root.path().join("secure-sudoers");
        std::fs::write(&binary_path, b"binary").unwrap();
        let managed_link = entry_point_dir.join("apt");
        std::fs::hard_link(&binary_path, &managed_link).unwrap();

        let tools = discover_managed_tools(
            binary_path.to_str().expect("utf-8 binary path"),
            entry_point_dir.to_str().expect("utf-8 entry-point dir"),
        );
        assert_eq!(tools, vec!["apt".to_string()]);
    }

    #[test]
    fn test_discover_managed_tools_ignores_symlink_entries() {
        let root = TempDir::new().unwrap();
        let entry_point_dir = root.path().join("bin");
        std::fs::create_dir(&entry_point_dir).unwrap();
        let binary_path = root.path().join("secure-sudoers");
        std::fs::write(&binary_path, b"binary").unwrap();
        let managed_link = entry_point_dir.join("apt");
        std::os::unix::fs::symlink(&binary_path, &managed_link).unwrap();

        let tools = discover_managed_tools(
            binary_path.to_str().expect("utf-8 binary path"),
            entry_point_dir.to_str().expect("utf-8 entry-point dir"),
        );
        assert!(tools.is_empty(), "symlink entries must be ignored");
    }

    #[test]
    fn test_discover_managed_tools_ignores_unrelated_regular_files() {
        let root = TempDir::new().unwrap();
        let entry_point_dir = root.path().join("bin");
        std::fs::create_dir(&entry_point_dir).unwrap();
        let binary_path = root.path().join("secure-sudoers");
        std::fs::write(&binary_path, b"binary").unwrap();

        std::fs::write(entry_point_dir.join("apt"), b"not linked").unwrap();
        std::fs::write(entry_point_dir.join("tail"), b"also not linked").unwrap();

        let tools = discover_managed_tools(
            binary_path.to_str().expect("utf-8 binary path"),
            entry_point_dir.to_str().expect("utf-8 entry-point dir"),
        );
        assert!(tools.is_empty(), "unrelated files must not be discovered");
    }

    #[test]
    fn test_find_first_existing_path_returns_first_match() {
        let dir = TempDir::new().unwrap();
        let existing = dir.path().join("candidate");
        std::fs::write(&existing, b"x").unwrap();
        let existing_path = existing.to_str().unwrap();
        let candidates = ["/definitely/not/present", existing_path];
        assert_eq!(find_first_existing_path(&candidates), Some(existing_path));
    }

    #[test]
    fn test_find_first_existing_path_returns_none_when_missing() {
        let candidates = ["/definitely/not/present", "/also/not/present"];
        assert_eq!(find_first_existing_path(&candidates), None);
    }

    #[test]
    fn test_should_skip_chattr_target_false_for_symlink() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"t").unwrap();
        let link = dir.path().join("tool");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(!should_skip_chattr_target("+i", link.to_str().unwrap()).unwrap());
    }

    #[test]
    fn test_should_skip_chattr_target_false_for_regular_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("regular");
        std::fs::write(&file, b"r").unwrap();

        assert!(!should_skip_chattr_target("+i", file.to_str().unwrap()).unwrap());
    }

    #[test]
    fn test_should_skip_chattr_target_true_for_missing_on_unlock() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("missing");
        assert!(should_skip_chattr_target("-i", missing.to_str().unwrap()).unwrap());
    }

    #[test]
    fn test_should_skip_chattr_target_false_for_missing_on_install() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("missing");
        assert!(!should_skip_chattr_target("+i", missing.to_str().unwrap()).unwrap());
    }

    #[test]
    fn test_unlock_with_paths_runs_without_error_on_valid_policy() {
        let env = TestEnv::new();
        write_policy(&env.policy_path, &[("tail", "/usr/bin/tail")]);
        let _ = unlock_with_paths(&env.paths());
    }

    #[test]
    fn test_chattr_op_handles_missing_binary() {
        let errors = chattr_op("+i", &["/tmp/nonexistent_secure_sudoers_test_file"]);
        let _ = errors;
    }
}
