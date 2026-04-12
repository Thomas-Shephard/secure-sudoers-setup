use crate::error::Error;
use crate::models::ValidationContext;
use base64::{Engine as _, prelude::BASE64_STANDARD};
use std::os::fd::AsRawFd;
use std::path::Path;

pub fn read_pem_bytes(path: &str, label: &str) -> Result<Vec<u8>, Error> {
    read_pem_bytes_with_before_read(path, label, || {})
}

fn read_pem_bytes_with_before_read<F>(
    path: &str,
    label: &str,
    before_read: F,
) -> Result<Vec<u8>, Error>
where
    F: FnOnce(),
{
    let content = read_file_to_string_securely(path, before_read)?;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let b64_content: String = content
        .lines()
        .skip_while(|l| *l != begin.as_str())
        .skip(1)
        .take_while(|l| *l != end.as_str())
        .map(|l| l.trim())
        .collect();
    if b64_content.is_empty() {
        return Err(Error::Parse(format!(
            "No '{label}' section found in PEM file {path}"
        )));
    }
    base64_to_bytes(&b64_content).map_err(|e| {
        Error::Parse(format!(
            "Invalid base64 in '{label}' section of {path}: {e}"
        ))
    })
}

fn read_file_to_string_securely<F>(path: &str, before_read: F) -> Result<String, Error>
where
    F: FnOnce(),
{
    let absolute_path = if Path::new(path).is_absolute() {
        Path::new(path).to_path_buf()
    } else {
        let cwd = std::env::current_dir().map_err(|e| {
            Error::IoContext(
                format!("Cannot resolve current directory while reading {path}"),
                e,
            )
        })?;
        cwd.join(path)
    };
    let absolute_path_str = absolute_path.to_str().ok_or_else(|| {
        Error::Validation(format!(
            "Path contains invalid UTF-8: {}",
            absolute_path.display()
        ))
    })?;

    let secure_path = crate::fs::check_path(absolute_path_str, &ValidationContext::Positional, &[])
        .map_err(|e| Error::Validation(format!("Cannot read {path}: {e}")))?;

    before_read();

    let proc_fd_path = format!("/proc/self/fd/{}", secure_path.fd.as_raw_fd());
    std::fs::read_to_string(&proc_fd_path)
        .map_err(|e| Error::IoContext(format!("Cannot read {path}"), e))
}

pub fn bytes_to_base64(bytes: &[u8]) -> String {
    BASE64_STANDARD.encode(bytes)
}

pub fn base64_to_bytes(b64: &str) -> Result<Vec<u8>, Error> {
    BASE64_STANDARD
        .decode(b64.trim())
        .map_err(|e| Error::Parse(format!("Invalid base64: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pem_bytes(label: &str, payload: &[u8]) -> String {
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            bytes_to_base64(payload)
        )
    }

    #[test]
    fn test_read_pem_bytes_uses_fd_anchored_content_after_symlink_swap() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let label = "SECURE SUDOERS PUBLIC KEY";

        let original_bytes = vec![1_u8, 2, 3, 4];
        let swapped_bytes = vec![9_u8, 8, 7, 6];

        let original_path = tmp.path().join("original.pem");
        let swapped_path = tmp.path().join("swapped.pem");
        let key_link = tmp.path().join("key.pem");

        std::fs::write(&original_path, pem_bytes(label, &original_bytes)).unwrap();
        std::fs::write(&swapped_path, pem_bytes(label, &swapped_bytes)).unwrap();
        symlink(&original_path, &key_link).unwrap();

        let loaded = read_pem_bytes_with_before_read(key_link.to_str().unwrap(), label, || {
            std::fs::remove_file(&key_link).unwrap();
            symlink(&swapped_path, &key_link).unwrap();
        })
        .unwrap();

        assert_eq!(
            loaded, original_bytes,
            "PEM bytes should be read from the already-validated file descriptor"
        );
    }

    #[test]
    fn test_read_pem_bytes_missing_path_reports_cannot_read() {
        let tmp = tempfile::tempdir().unwrap();
        let missing_path = tmp.path().join("missing.pem");
        let err = read_pem_bytes(missing_path.to_str().unwrap(), "SECURE SUDOERS PUBLIC KEY")
            .unwrap_err();
        assert!(
            err.to_string().contains("Cannot read"),
            "unexpected error: {err}"
        );
    }
}
