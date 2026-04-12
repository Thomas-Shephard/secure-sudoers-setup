#![cfg(target_os = "linux")]

use clap::{CommandFactory, Parser, Subcommand};
use secure_sudoers_common::error::Error;
use secure_sudoers_common::kernel;
use secure_sudoers_common::models::{SecurePath, ValidationContext};
#[cfg(feature = "network-update")]
use secure_sudoers_utils::modules::network;
use secure_sudoers_utils::modules::{installer, keys};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "secure-sudoers-utils",
    about = "Policy key management and distribution for secure-sudoers"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Ed25519 keypair
    GenKeys,
    /// Sign a policy JSON file with the private key
    Sign {
        policy_path: String,
        key_path: String,
    },
    /// Securely fetch and apply a signed policy update
    #[cfg(feature = "network-update")]
    Update { url: String, pubkey_path: String },
    /// Install secure-sudoers system-wide
    Install,
    /// Remove the immutable bit from all managed files
    Unlock,
    /// Validate a policy JSON file for correctness and best practices
    Check { policy_path: String },
    #[command(hide = true, name = "generate-man-page")]
    GenerateManPage,
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = kernel::ensure_minimum_kernel_version() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }

    if !matches!(
        cli.command,
        Commands::GenerateManPage | Commands::Check { .. }
    ) && let Err(e) = secure_sudoers_utils::require_root()
    {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }

    let result = match cli.command {
        Commands::GenKeys => keys::cmd_gen_keys(),
        Commands::Sign {
            policy_path,
            key_path,
        } => cmd_sign(&policy_path, &key_path),
        #[cfg(feature = "network-update")]
        Commands::Update { url, pubkey_path } => network::run(&url, &pubkey_path),
        Commands::Install => installer::cmd_install(),
        Commands::Unlock => installer::cmd_unlock(),
        Commands::Check { policy_path } => cmd_check(&policy_path),
        Commands::GenerateManPage => cmd_generate_man_page(),
    };
    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn cmd_check(policy_path: &str) -> Result<(), Error> {
    cmd_check_with_before_read(policy_path, || {})
}

fn cmd_check_with_before_read<F>(policy_path: &str, before_read: F) -> Result<(), Error>
where
    F: FnOnce(),
{
    let content = read_file_to_string_securely_with_before_read(policy_path, before_read)?;

    let mut policy: secure_sudoers_common::models::SecureSudoersPolicy =
        serde_json::from_str(&content)
            .map_err(|e| Error::Parse(format!("Failed to parse policy JSON: {e}")))?;

    let issues = policy.lint();
    if issues.is_empty() {
        println!("Policy '{policy_path}' is valid.");
        Ok(())
    } else {
        eprintln!("Policy '{policy_path}' has the following issues:");
        for issue in issues {
            eprintln!("  - {issue}");
        }
        Err(Error::Validation("Policy check failed".to_string()))
    }
}

fn cmd_sign(policy_path: &str, key_path: &str) -> Result<(), Error> {
    cmd_sign_with_before_read(policy_path, key_path, || {})
}

fn cmd_sign_with_before_read<F>(
    policy_path: &str,
    key_path: &str,
    before_read: F,
) -> Result<(), Error>
where
    F: FnOnce(),
{
    let signing_key = keys::load_signing_key(key_path)?;
    let policy_bytes = read_file_bytes_securely_with_before_read(policy_path, before_read)?;
    let signature = ed25519_dalek::Signer::sign(&signing_key, &policy_bytes);
    let signature_bytes = signature.to_bytes();
    let sig_path = format!("{policy_path}.sig");
    write_file_securely_without_following_symlinks(&sig_path, &signature_bytes)?;
    println!("Signed {policy_path} → {sig_path}");
    Ok(())
}

fn read_file_to_string_securely_with_before_read<F>(
    path: &str,
    before_read: F,
) -> Result<String, Error>
where
    F: FnOnce(),
{
    read_file_securely_with_before_read(path, before_read, |proc_fd_path| {
        std::fs::read_to_string(proc_fd_path)
    })
}

fn read_file_bytes_securely_with_before_read<F>(
    path: &str,
    before_read: F,
) -> Result<Vec<u8>, Error>
where
    F: FnOnce(),
{
    read_file_securely_with_before_read(path, before_read, |proc_fd_path| {
        std::fs::read(proc_fd_path)
    })
}

fn read_file_securely_with_before_read<T, FBeforeRead, FRead>(
    path: &str,
    before_read: FBeforeRead,
    read_op: FRead,
) -> Result<T, Error>
where
    FBeforeRead: FnOnce(),
    FRead: FnOnce(&str) -> std::io::Result<T>,
{
    let secure_path = open_path_securely_for_read(path)?;
    before_read();
    let proc_fd_path = format!("/proc/self/fd/{}", secure_path.fd.as_raw_fd());
    read_op(&proc_fd_path).map_err(|e| Error::IoContext(format!("Cannot read {path}"), e))
}

fn write_file_securely_without_following_symlinks(path: &str, bytes: &[u8]) -> Result<(), Error> {
    write_file_securely_without_following_symlinks_with_before_open(path, bytes, || {})
}

fn write_file_securely_without_following_symlinks_with_before_open<F>(
    path: &str,
    bytes: &[u8],
    before_open: F,
) -> Result<(), Error>
where
    F: FnOnce(),
{
    let absolute_path = resolve_absolute_path(path, "writing")?;
    let parent = absolute_path.parent().ok_or_else(|| {
        Error::System(format!(
            "Cannot securely write {path}: missing parent directory for {}",
            absolute_path.display()
        ))
    })?;
    let parent_str = parent.to_str().ok_or_else(|| {
        Error::Validation(format!("Path contains invalid UTF-8: {}", parent.display()))
    })?;
    let secure_parent =
        secure_sudoers_common::fs::check_path(parent_str, &ValidationContext::Positional, &[])
            .map_err(|e| {
                Error::Validation(format!(
                    "Cannot securely open parent directory of {path}: {e}"
                ))
            })?;

    let file_name = absolute_path.file_name().ok_or_else(|| {
        Error::System(format!(
            "Cannot securely write {path}: missing file name in {}",
            absolute_path.display()
        ))
    })?;
    let file_name_str = file_name.to_str().ok_or_else(|| {
        Error::Validation(format!(
            "Path contains invalid UTF-8 file name: {}",
            absolute_path.display()
        ))
    })?;
    let file_name_c = std::ffi::CString::new(file_name_str)
        .map_err(|_| Error::System(format!("Path contains NUL byte in file name: {path}")))?;

    before_open();

    let fd = unsafe {
        libc::openat(
            secure_parent.fd.as_raw_fd(),
            file_name_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o666,
        )
    };
    if fd < 0 {
        return Err(Error::IoContext(
            format!("Failed to securely open {path} for writing"),
            std::io::Error::last_os_error(),
        ));
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(bytes)
        .map_err(|e| Error::IoContext(format!("Failed to write {path}"), e))
}

fn open_path_securely_for_read(path: &str) -> Result<SecurePath, Error> {
    let absolute_path = resolve_absolute_path(path, "reading")?;
    let absolute_path_str = absolute_path.to_str().ok_or_else(|| {
        Error::Validation(format!(
            "Path contains invalid UTF-8: {}",
            absolute_path.display()
        ))
    })?;

    secure_sudoers_common::fs::check_path(absolute_path_str, &ValidationContext::Positional, &[])
        .map_err(|e| Error::Validation(format!("Cannot read {path}: {e}")))
}

fn resolve_absolute_path(path: &str, action: &str) -> Result<PathBuf, Error> {
    if Path::new(path).is_absolute() {
        Ok(Path::new(path).to_path_buf())
    } else {
        let cwd = std::env::current_dir().map_err(|e| {
            Error::IoContext(
                format!("Cannot resolve current directory while {action} {path}"),
                e,
            )
        })?;
        Ok(cwd.join(path))
    }
}

fn cmd_generate_man_page() -> Result<(), Error> {
    let cmd = Cli::command();
    let man = clap_mangen::Man::new(cmd);
    let mut buffer: Vec<u8> = Default::default();
    man.render(&mut buffer)
        .map_err(|e| Error::IoContext("Failed to render man page".to_string(), e))?;
    std::io::Write::write_all(&mut std::io::stdout(), &buffer)
        .map_err(|e| Error::IoContext("Failed to write to stdout".to_string(), e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, SigningKey, Verifier};
    use rand_core::OsRng;

    #[test]
    fn test_cmd_check_reads_from_fd_anchored_policy_after_symlink_swap() {
        use secure_sudoers_common::testing::fixtures;
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let original_path = tmp.path().join("policy-original.json");
        let swapped_path = tmp.path().join("policy-swapped.json");
        let policy_link = tmp.path().join("policy.json");

        let valid_policy_json = serde_json::to_string(&fixtures::make_valid_policy()).unwrap();
        std::fs::write(&original_path, valid_policy_json).unwrap();
        std::fs::write(&swapped_path, "{ this is invalid json").unwrap();
        symlink(&original_path, &policy_link).unwrap();

        let result = super::cmd_check_with_before_read(policy_link.to_str().unwrap(), || {
            std::fs::remove_file(&policy_link).unwrap();
            symlink(&swapped_path, &policy_link).unwrap();
        });

        assert!(
            result.is_ok(),
            "cmd_check should validate the originally opened policy inode, got {result:?}"
        );
    }

    #[test]
    fn test_cmd_sign_reads_from_fd_anchored_policy_after_symlink_swap() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("private.pem");
        let original_path = tmp.path().join("policy-original.json");
        let swapped_path = tmp.path().join("policy-swapped.json");
        let policy_link = tmp.path().join("policy.json");

        let signing_key = SigningKey::generate(&mut OsRng);
        super::keys::write_key_file(
            key_path.to_str().unwrap(),
            "SECURE SUDOERS PRIVATE KEY",
            &signing_key.to_bytes(),
            0o600,
        )
        .unwrap();

        let original_policy = br#"{"serial":1}"#;
        let swapped_policy = br#"{"serial":999}"#;
        std::fs::write(&original_path, original_policy).unwrap();
        std::fs::write(&swapped_path, swapped_policy).unwrap();
        symlink(&original_path, &policy_link).unwrap();

        super::cmd_sign_with_before_read(
            policy_link.to_str().unwrap(),
            key_path.to_str().unwrap(),
            || {
                std::fs::remove_file(&policy_link).unwrap();
                symlink(&swapped_path, &policy_link).unwrap();
            },
        )
        .unwrap();

        let sig_path = format!("{}.sig", policy_link.to_str().unwrap());
        let sig_bytes = std::fs::read(sig_path).unwrap();
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
        let signature = Signature::from_bytes(&sig_arr);
        let verifying_key = signing_key.verifying_key();

        assert!(verifying_key.verify(original_policy, &signature).is_ok());
        assert!(verifying_key.verify(swapped_policy, &signature).is_err());
    }

    #[test]
    fn test_cmd_sign_rejects_symlink_signature_output_path() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("private.pem");
        let policy_path = tmp.path().join("policy.json");
        let victim_path = tmp.path().join("victim.txt");
        let sig_path = format!("{}.sig", policy_path.to_str().unwrap());

        let signing_key = SigningKey::generate(&mut OsRng);
        super::keys::write_key_file(
            key_path.to_str().unwrap(),
            "SECURE SUDOERS PRIVATE KEY",
            &signing_key.to_bytes(),
            0o600,
        )
        .unwrap();

        std::fs::write(&policy_path, br#"{"serial":1}"#).unwrap();
        std::fs::write(&victim_path, b"do-not-overwrite").unwrap();
        symlink(&victim_path, &sig_path).unwrap();

        let result = super::cmd_sign(policy_path.to_str().unwrap(), key_path.to_str().unwrap());
        assert!(
            result.is_err(),
            "signing should fail for symlink signature path"
        );
        assert_eq!(
            std::fs::read(&victim_path).unwrap(),
            b"do-not-overwrite",
            "symlink target should remain unchanged"
        );
    }

    #[test]
    fn test_secure_write_anchors_parent_directory_fd_after_symlink_swap() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let trusted_parent = tmp.path().join("trusted-parent");
        let attacker_parent = tmp.path().join("attacker-parent");
        let linked_parent = tmp.path().join("parent-link");

        std::fs::create_dir(&trusted_parent).unwrap();
        std::fs::create_dir(&attacker_parent).unwrap();
        symlink(&trusted_parent, &linked_parent).unwrap();

        let write_path = linked_parent.join("policy.sig");
        let trusted_target = trusted_parent.join("policy.sig");
        let attacker_target = attacker_parent.join("policy.sig");

        super::write_file_securely_without_following_symlinks_with_before_open(
            write_path.to_str().unwrap(),
            b"sig-bytes",
            || {
                std::fs::remove_file(&linked_parent).unwrap();
                symlink(&attacker_parent, &linked_parent).unwrap();
            },
        )
        .unwrap();

        assert_eq!(std::fs::read(&trusted_target).unwrap(), b"sig-bytes");
        assert!(
            !attacker_target.exists(),
            "write should stay anchored to originally validated parent directory"
        );
    }

    #[test]
    fn test_keygen_sign_verify_roundtrip() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let payload = b"dummy policy payload";
        let signature: Signature = ed25519_dalek::Signer::sign(&signing_key, payload);
        assert!(verifying_key.verify(payload, &signature).is_ok());
    }
}
