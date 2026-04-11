use super::config::ENTRY_POINT_DIR;
use secure_sudoers_common::error::Error;

pub fn generate_sudoers_content(tools: &[String]) -> String {
    generate_sudoers_content_with_dir(tools, ENTRY_POINT_DIR)
}

pub(super) fn generate_sudoers_content_with_dir(tools: &[String], entry_point_dir: &str) -> String {
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

pub(super) fn write_sudoers_file_to(
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
            match std::fs::remove_file(&self.path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    eprintln!(
                        "Warning: failed to clean up temporary sudoers file {}: {e}",
                        self.path.display()
                    );
                }
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
