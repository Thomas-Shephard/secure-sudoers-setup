use super::keys::load_verifying_key;
use ed25519_dalek::{Signature, Verifier};
use secure_sudoers_common::error::Error;
use secure_sudoers_common::models::SecureSudoersPolicy;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const MAX_POLICY_BYTES: usize = 1024 * 1024;
const POLICY_PATH: &str = "/etc/secure-sudoers/policy.json";
const DEFAULT_POLICY_MODE: u32 = 0o600;
const MAX_ROLLBACK_SIGNATURE_BYTES: usize = 1024;
const LINUX_FS_IMMUTABLE_FL: libc::c_int = 0x0000_0010;

pub fn run(url: &str, pubkey_path: &str) -> Result<(), Error> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .https_only(true)
        .build()
        .map_err(|e| Error::System(format!("Failed to build HTTP client: {e}")))?;
    run_with_client(&client, url, pubkey_path, POLICY_PATH, true)
}

fn run_with_client(
    client: &reqwest::blocking::Client,
    url: &str,
    pubkey_path: &str,
    policy_path: &str,
    require_https: bool,
) -> Result<(), Error> {
    let policy_url = parse_policy_url(url)?;
    if require_https && policy_url.scheme() != "https" {
        let safe_url = sanitize_url_for_logs(&policy_url);
        return Err(Error::Security(format!(
            "Security violation: URL must use HTTPS. Received: {safe_url}"
        )));
    }
    let sig_url = signature_url_for_policy(&policy_url);

    let policy_bytes = fetch_limited(client, &policy_url)?;
    let sig_bytes = fetch_limited(client, &sig_url)?;

    let verifying_key = load_verifying_key(pubkey_path)?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        Error::Validation(format!(
            "Signature must be 64 bytes; got {}",
            sig_bytes.len()
        ))
    })?;
    verifying_key
        .verify(&policy_bytes, &Signature::from_bytes(&sig_arr))
        .map_err(|e| Error::Security(format!("Signature verification failed: {e}")))?;

    let mut new_policy: SecureSudoersPolicy = serde_json::from_slice(&policy_bytes)
        .map_err(|e| Error::Parse(format!("Downloaded policy is not valid JSON: {e}")))?;
    new_policy.validate().map_err(|e| {
        Error::Validation(format!("Downloaded policy failed semantic validation: {e}"))
    })?;

    let current_serial = std::fs::read_to_string(policy_path)
        .ok()
        .and_then(|current_src| serde_json::from_str::<SecureSudoersPolicy>(&current_src).ok())
        .map(|current| current.serial);
    if let Some(current_serial) = current_serial.filter(|serial| new_policy.serial <= *serial) {
        return Err(Error::Config(format!(
            "Downgrade rejected: incoming serial {} <= current serial {}",
            new_policy.serial, current_serial
        )));
    }

    install_update(policy_path, &policy_bytes, &sig_bytes)?;

    println!(
        "Policy and signature updated to serial {} and installed at {}",
        new_policy.serial, policy_path
    );
    Ok(())
}

fn parse_policy_url(url: &str) -> Result<reqwest::Url, Error> {
    reqwest::Url::parse(url).map_err(|_| {
        Error::Parse(format!(
            "Invalid policy URL: {}",
            sanitize_url_for_logs_from_str(url)
        ))
    })
}

fn signature_url_for_policy(policy_url: &reqwest::Url) -> reqwest::Url {
    let mut sig_url = policy_url.clone();
    let mut path = sig_url.path().to_string();
    path.push_str(".sig");
    sig_url.set_path(&path);
    sig_url.set_fragment(None);
    sig_url
}

fn sanitize_url_for_logs(url: &reqwest::Url) -> String {
    let mut parsed = url.clone();
    parsed.set_query(None);
    parsed.set_fragment(None);
    if parsed.password().is_some() {
        let _ = parsed.set_password(Some("REDACTED"));
    }
    if !parsed.username().is_empty() {
        let _ = parsed.set_username("REDACTED");
    }
    parsed.to_string()
}

fn sanitize_url_for_logs_from_str(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(parsed) => sanitize_url_for_logs(&parsed),
        Err(_) => "<redacted-invalid-url>".to_string(),
    }
}

fn install_update(policy_path: &str, policy_bytes: &[u8], sig_bytes: &[u8]) -> Result<(), Error> {
    let policy_dir = Path::new(policy_path)
        .parent()
        .unwrap_or_else(|| Path::new("/etc/secure-sudoers"));
    let sig_path = format!("{policy_path}.sig");
    let sig_path_ref = Path::new(&sig_path);
    let previous_sig = read_existing_signature_for_rollback(sig_path_ref).map_err(|e| {
        Error::IoContext(
            format!("Failed to read existing signature at {sig_path}"),
            e,
        )
    })?;
    let sig_mode = read_existing_mode(sig_path_ref)
        .map_err(|e| Error::IoContext(format!("Cannot read metadata for {sig_path}"), e))?;
    let sig_was_immutable = read_existing_immutable(sig_path_ref)
        .map_err(|e| Error::IoContext(format!("Cannot inspect immutable flag for {sig_path}"), e))?
        .unwrap_or(false);
    let policy_mode = read_existing_mode(Path::new(policy_path))
        .map_err(|e| Error::IoContext(format!("Cannot read metadata for {policy_path}"), e))?;
    let policy_was_immutable = read_existing_immutable(Path::new(policy_path))
        .map_err(|e| {
            Error::IoContext(
                format!("Cannot inspect immutable flag for {policy_path}"),
                e,
            )
        })?
        .unwrap_or(false);

    let mut tmp_sig = tempfile::NamedTempFile::new_in(policy_dir).map_err(|e| {
        Error::IoContext(
            format!("Cannot create temp sig file in {}", policy_dir.display()),
            e,
        )
    })?;
    tmp_sig
        .write_all(sig_bytes)
        .map_err(|e| Error::IoContext("Failed to write temp sig file".to_string(), e))?;
    tmp_sig
        .as_file()
        .sync_all()
        .map_err(|e| Error::IoContext("Failed to sync temp sig file".to_string(), e))?;
    apply_mode_if_present(tmp_sig.as_file(), sig_mode.or(Some(DEFAULT_POLICY_MODE))).map_err(
        |e| Error::IoContext("Failed to set permissions on temp sig file".to_string(), e),
    )?;

    let mut tmp_policy = tempfile::NamedTempFile::new_in(policy_dir).map_err(|e| {
        Error::IoContext(
            format!("Cannot create temp policy file in {}", policy_dir.display()),
            e,
        )
    })?;
    tmp_policy
        .write_all(policy_bytes)
        .map_err(|e| Error::IoContext("Failed to write temp policy file".to_string(), e))?;
    tmp_policy
        .as_file()
        .sync_all()
        .map_err(|e| Error::IoContext("Failed to sync temp policy file".to_string(), e))?;
    apply_mode_if_present(
        tmp_policy.as_file(),
        policy_mode.or(Some(DEFAULT_POLICY_MODE)),
    )
    .map_err(|e| {
        Error::IoContext(
            "Failed to set permissions on temp policy file".to_string(),
            e,
        )
    })?;

    tmp_sig
        .persist(&sig_path)
        .map_err(|e| Error::IoContext("Atomic rename of signature failed".to_string(), e.error))?;

    run_with_signature_rollback(
        &sig_path,
        previous_sig.as_deref(),
        sig_mode,
        sig_was_immutable,
        move || {
            tmp_policy.persist(policy_path).map_err(|e| {
                Error::IoContext("Atomic rename of policy failed".to_string(), e.error)
            })?;
            Ok(())
        },
    )?;
    restore_immutable_if_needed(
        &sig_path,
        policy_path,
        sig_was_immutable,
        policy_was_immutable,
    )?;

    Ok(())
}

fn run_with_signature_rollback<F>(
    sig_path: &str,
    previous_sig: Option<&[u8]>,
    previous_sig_mode: Option<u32>,
    previous_sig_was_immutable: bool,
    policy_step: F,
) -> Result<(), Error>
where
    F: FnOnce() -> Result<(), Error>,
{
    if let Err(err) = policy_step() {
        let err_msg = err.to_string();
        if let Err(rollback_err) = restore_signature(
            sig_path,
            previous_sig,
            previous_sig_mode,
            previous_sig_was_immutable,
        ) {
            return Err(Error::System(format!(
                "Policy update failed ({err_msg}); signature rollback also failed at {sig_path}: {rollback_err}"
            )));
        }
        return Err(err);
    }

    Ok(())
}

fn read_existing_signature_for_rollback(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    use std::io::Read;

    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };

    let mut bytes = Vec::with_capacity(64);
    file.take((MAX_ROLLBACK_SIGNATURE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_ROLLBACK_SIGNATURE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "existing signature exceeds {} bytes",
                MAX_ROLLBACK_SIGNATURE_BYTES
            ),
        ));
    }

    Ok(Some(bytes))
}

fn read_existing_immutable(path: &Path) -> std::io::Result<Option<bool>> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };

    let mut flags: libc::c_int = 0;
    let rc = unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_GETFLAGS as _, &mut flags) };
    if rc == 0 {
        return Ok(Some((flags & LINUX_FS_IMMUTABLE_FL) != 0));
    }

    let e = std::io::Error::last_os_error();
    match e.raw_os_error() {
        Some(code) if code == libc::ENOTTY || code == libc::EOPNOTSUPP || code == libc::EINVAL => {
            Ok(Some(false))
        }
        _ => Err(e),
    }
}

fn restore_immutable_if_needed(
    sig_path: &str,
    policy_path: &str,
    sig_was_immutable: bool,
    policy_was_immutable: bool,
) -> Result<(), Error> {
    let mut targets: Vec<&str> = Vec::new();
    if sig_was_immutable {
        targets.push(sig_path);
    }
    if policy_was_immutable {
        targets.push(policy_path);
    }

    if targets.is_empty() {
        return Ok(());
    }

    let errors = super::installer::immutable::chattr_op("+i", &targets);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(Error::System(format!(
            "Failed to restore immutable attribute (+i) on updated file(s):\n{}",
            errors.join("\n")
        )))
    }
}

fn read_existing_mode(path: &Path) -> std::io::Result<Option<u32>> {
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(Some(metadata.permissions().mode() & 0o777)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn apply_mode_if_present(file: &std::fs::File, mode: Option<u32>) -> std::io::Result<()> {
    if let Some(mode) = mode {
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

fn restore_signature(
    sig_path: &str,
    previous_sig: Option<&[u8]>,
    previous_sig_mode: Option<u32>,
    previous_sig_was_immutable: bool,
) -> std::io::Result<()> {
    match previous_sig {
        Some(bytes) => {
            let path = Path::new(sig_path);
            let dir = path.parent().unwrap_or_else(|| Path::new("."));
            let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
            tmp.write_all(bytes)?;
            apply_mode_if_present(
                tmp.as_file(),
                previous_sig_mode.or(Some(DEFAULT_POLICY_MODE)),
            )?;
            tmp.as_file().sync_all()?;
            tmp.persist(sig_path).map_err(|e| e.error)?;
            if previous_sig_was_immutable {
                let errors = super::installer::immutable::chattr_op("+i", &[sig_path]);
                if !errors.is_empty() {
                    return Err(std::io::Error::other(format!(
                        "failed to restore immutable attribute (+i): {}",
                        errors.join("; ")
                    )));
                }
            }
            Ok(())
        }
        None => match std::fs::remove_file(sig_path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        },
    }
}

fn fetch_limited(client: &reqwest::blocking::Client, url: &reqwest::Url) -> Result<Vec<u8>, Error> {
    use std::io::Read;
    let safe_url = sanitize_url_for_logs(url);
    let response = client.get(url.clone()).send().map_err(|e| {
        let reason = if e.is_timeout() {
            "request timed out"
        } else if e.is_connect() {
            "connection failed"
        } else if e.is_request() {
            "request build failed"
        } else {
            "request failed"
        };
        Error::Network(format!("GET {safe_url} failed: {reason}"))
    })?;
    if !response.status().is_success() {
        return Err(Error::Network(format!(
            "HTTP {} for {safe_url}",
            response.status()
        )));
    }
    if let Some(content_len) = response
        .content_length()
        .filter(|content_len| *content_len > MAX_POLICY_BYTES as u64)
    {
        return Err(Error::Config(format!(
            "Server Content-Length {content_len} exceeds {MAX_POLICY_BYTES}-byte limit"
        )));
    }

    let mut buffer = response
        .content_length()
        .map(|len| len as usize)
        .map(Vec::with_capacity)
        .unwrap_or_default();
    response
        .take((MAX_POLICY_BYTES + 1) as u64)
        .read_to_end(&mut buffer)
        .map_err(|e| Error::IoContext(format!("Failed to read body of {safe_url}"), e))?;

    if buffer.len() > MAX_POLICY_BYTES {
        return Err(Error::Config(format!(
            "Response body exceeds {MAX_POLICY_BYTES}-byte limit"
        )));
    }
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::keys::write_key_file;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use secure_sudoers_common::testing::fixtures::make_valid_policy;
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::thread;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    #[derive(Clone)]
    struct FixtureResponse {
        status_code: u16,
        content_length_override: Option<usize>,
        body: Vec<u8>,
    }

    impl FixtureResponse {
        fn ok(body: Vec<u8>) -> Self {
            Self {
                status_code: 200,
                content_length_override: None,
                body,
            }
        }

        fn with_content_length_override(mut self, content_length: usize) -> Self {
            self.content_length_override = Some(content_length);
            self
        }

        fn not_found() -> Self {
            Self {
                status_code: 404,
                content_length_override: None,
                body: b"not found".to_vec(),
            }
        }
    }

    struct HttpFixture {
        base_url: String,
        handle: thread::JoinHandle<()>,
    }

    impl HttpFixture {
        fn join(self) {
            self.handle
                .join()
                .expect("fixture server thread should finish cleanly");
        }
    }

    fn spawn_http_fixture(
        expected_requests: usize,
        routes: HashMap<String, FixtureResponse>,
    ) -> HttpFixture {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("fixture should bind an ephemeral port");
        listener
            .set_nonblocking(true)
            .expect("fixture listener should be non-blocking");
        let addr = listener
            .local_addr()
            .expect("fixture should expose local address");

        let handle = thread::spawn(move || {
            let mut served = 0usize;
            let deadline = Instant::now() + Duration::from_secs(10);
            while served < expected_requests {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let path = read_request_path(&mut stream);
                        let response = routes
                            .get(&path)
                            .cloned()
                            .unwrap_or_else(FixtureResponse::not_found);
                        write_response(&mut stream, &response);
                        served += 1;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "fixture timed out after serving {served}/{expected_requests} requests"
                        );
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(e) => panic!("fixture accept failed: {e}"),
                }
            }
        });

        HttpFixture {
            base_url: format!("http://{addr}"),
            handle,
        }
    }

    fn read_request_path(stream: &mut TcpStream) -> String {
        let mut reader = BufReader::new(
            stream
                .try_clone()
                .expect("fixture stream clone should succeed"),
        );

        let mut request_line = String::new();
        reader
            .read_line(&mut request_line)
            .expect("fixture should read request line");
        let path = request_line
            .split_whitespace()
            .nth(1)
            .unwrap_or("/")
            .to_string();

        loop {
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("fixture should read request header");
            if line == "\r\n" || line.is_empty() {
                break;
            }
        }

        path
    }

    fn write_response(stream: &mut TcpStream, response: &FixtureResponse) {
        let reason = match response.status_code {
            200 => "OK",
            404 => "Not Found",
            _ => "Error",
        };
        let content_length = response
            .content_length_override
            .unwrap_or(response.body.len());

        let headers = format!(
            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response.status_code, reason, content_length
        );
        stream
            .write_all(headers.as_bytes())
            .expect("fixture should write response headers");
        stream
            .write_all(&response.body)
            .expect("fixture should write response body");
        stream.flush().expect("fixture should flush response");
    }

    fn write_test_public_key(path: &Path, signing_key: &SigningKey) {
        write_key_file(
            path.to_str().expect("test key path must be valid UTF-8"),
            "SECURE SUDOERS PUBLIC KEY",
            &signing_key.verifying_key().to_bytes(),
            0o644,
        )
        .expect("test public key should be writable");
    }

    fn policy_json(serial: i32) -> Vec<u8> {
        let mut policy = make_valid_policy();
        policy.serial = serial;
        serde_json::to_vec(&policy).expect("test policy should serialize")
    }

    fn run_update_for_test(url: &str, pubkey_path: &Path, policy_path: &Path) -> Result<(), Error> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("test HTTP client should build");
        run_with_client(
            &client,
            url,
            pubkey_path
                .to_str()
                .expect("pubkey path must be valid UTF-8"),
            policy_path
                .to_str()
                .expect("policy path must be valid UTF-8"),
            false,
        )
    }

    #[test]
    fn sanitize_url_for_logs_strips_sensitive_components() {
        let url =
            reqwest::Url::parse("https://alice:secret@example.com/policy.json?token=abc#frag")
                .expect("test URL should parse");
        let redacted = sanitize_url_for_logs(&url);
        assert!(!redacted.contains("alice"), "username should be redacted");
        assert!(!redacted.contains("secret"), "password should be redacted");
        assert!(!redacted.contains("token=abc"), "query should be redacted");
        assert!(!redacted.contains("frag"), "fragment should be redacted");
        assert!(
            redacted.contains("example.com/policy.json"),
            "host and path should remain visible"
        );
    }

    #[test]
    fn sanitize_url_for_logs_redacts_unparseable_input() {
        let redacted = sanitize_url_for_logs_from_str("not a url with token=secret");
        assert_eq!(redacted, "<redacted-invalid-url>");
    }

    #[test]
    fn parse_policy_url_error_redacts_unparseable_input() {
        let err = parse_policy_url("not a url with token=supersecret")
            .expect_err("unparseable URL should fail");
        match err {
            Error::Parse(msg) => {
                assert!(
                    !msg.contains("supersecret"),
                    "parse error should not leak input secrets"
                );
                assert!(
                    msg.contains("<redacted-invalid-url>"),
                    "parse error should reference redacted URL marker"
                );
            }
            other => panic!("expected parse error, got: {other}"),
        }
    }

    #[test]
    fn signature_url_for_policy_rewrites_path_and_preserves_query() {
        let policy_url = reqwest::Url::parse("https://example.com/a/policy.json?v=1#frag")
            .expect("policy URL should parse");
        let sig_url = signature_url_for_policy(&policy_url);
        assert_eq!(sig_url.path(), "/a/policy.json.sig");
        assert_eq!(sig_url.query(), Some("v=1"));
        assert_eq!(sig_url.fragment(), None);
        assert_eq!(
            sig_url.as_str(),
            "https://example.com/a/policy.json.sig?v=1"
        );
    }

    #[test]
    fn require_https_error_redacts_url_secrets() {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(1))
            .build()
            .expect("test HTTP client should build");
        let err = run_with_client(
            &client,
            "http://example.invalid/policy.json?token=supersecret#frag",
            "/unused",
            "/unused",
            true,
        )
        .expect_err("non-HTTPS URLs should be rejected");

        match err {
            Error::Security(msg) => {
                assert!(
                    !msg.contains("token=supersecret"),
                    "error must not leak query secrets"
                );
                assert!(!msg.contains("frag"), "error must not leak fragments");
                assert!(msg.contains("example.invalid/policy.json"));
            }
            other => panic!("expected security error, got: {other}"),
        }
    }

    #[test]
    fn fetch_limited_error_redacts_url_secrets() {
        let fixture = spawn_http_fixture(1, HashMap::new());
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("test HTTP client should build");
        let sensitive_url = reqwest::Url::parse(&format!(
            "{}/policy.json?token=supersecret#frag",
            fixture.base_url
        ))
        .expect("sensitive URL should parse");

        let err =
            fetch_limited(&client, &sensitive_url).expect_err("missing route should produce 404");
        fixture.join();

        match err {
            Error::Network(msg) => {
                assert!(
                    !msg.contains("token=supersecret"),
                    "error must not leak query secrets"
                );
                assert!(!msg.contains("frag"), "error must not leak fragments");
                assert!(msg.contains("/policy.json"), "path context should remain");
            }
            other => panic!("expected network error, got: {other}"),
        }
    }

    #[test]
    fn update_success_replaces_policy_and_signature() {
        let temp = TempDir::new().expect("test tempdir should be created");
        let policy_path = temp.path().join("policy.json");
        let sig_path = temp.path().join("policy.json.sig");
        let pubkey_path = temp.path().join("secure_sudoers_public_key.pem");

        let signing_key = SigningKey::generate(&mut OsRng);
        write_test_public_key(&pubkey_path, &signing_key);

        std::fs::write(&policy_path, policy_json(1)).expect("seed policy should be writable");
        std::fs::write(&sig_path, vec![7u8; 64]).expect("seed signature should be writable");

        let new_policy = policy_json(2);
        let new_sig = signing_key.sign(&new_policy).to_bytes().to_vec();

        let mut routes = HashMap::new();
        routes.insert(
            "/policy.json".to_string(),
            FixtureResponse::ok(new_policy.clone()),
        );
        routes.insert(
            "/policy.json.sig".to_string(),
            FixtureResponse::ok(new_sig.clone()),
        );
        let fixture = spawn_http_fixture(2, routes);
        let url = format!("{}/policy.json", fixture.base_url);

        run_update_for_test(&url, &pubkey_path, &policy_path)
            .expect("valid update should be installed");
        fixture.join();

        assert_eq!(
            std::fs::read(&policy_path).expect("updated policy should be readable"),
            new_policy
        );
        assert_eq!(
            std::fs::read(&sig_path).expect("updated signature should be readable"),
            new_sig
        );
    }

    #[test]
    fn update_success_with_query_fetches_signature_from_sig_path() {
        let temp = TempDir::new().expect("test tempdir should be created");
        let policy_path = temp.path().join("policy.json");
        let sig_path = temp.path().join("policy.json.sig");
        let pubkey_path = temp.path().join("secure_sudoers_public_key.pem");

        let signing_key = SigningKey::generate(&mut OsRng);
        write_test_public_key(&pubkey_path, &signing_key);

        std::fs::write(&policy_path, policy_json(1)).expect("seed policy should be writable");
        std::fs::write(&sig_path, vec![7u8; 64]).expect("seed signature should be writable");

        let new_policy = policy_json(2);
        let new_sig = signing_key.sign(&new_policy).to_bytes().to_vec();

        let mut routes = HashMap::new();
        routes.insert(
            "/policy.json?v=1".to_string(),
            FixtureResponse::ok(new_policy.clone()),
        );
        routes.insert(
            "/policy.json.sig?v=1".to_string(),
            FixtureResponse::ok(new_sig.clone()),
        );
        let fixture = spawn_http_fixture(2, routes);
        let url = format!("{}/policy.json?v=1#ignored-fragment", fixture.base_url);

        run_update_for_test(&url, &pubkey_path, &policy_path)
            .expect("valid update with query should be installed");
        fixture.join();

        assert_eq!(
            std::fs::read(&policy_path).expect("updated policy should be readable"),
            new_policy
        );
        assert_eq!(
            std::fs::read(&sig_path).expect("updated signature should be readable"),
            new_sig
        );
    }

    #[test]
    fn update_success_uses_default_modes_when_targets_do_not_exist() {
        let temp = TempDir::new().expect("test tempdir should be created");
        let policy_path = temp.path().join("policy.json");
        let sig_path = temp.path().join("policy.json.sig");
        let pubkey_path = temp.path().join("secure_sudoers_public_key.pem");

        let signing_key = SigningKey::generate(&mut OsRng);
        write_test_public_key(&pubkey_path, &signing_key);

        let new_policy = policy_json(1);
        let new_sig = signing_key.sign(&new_policy).to_bytes().to_vec();

        let mut routes = HashMap::new();
        routes.insert(
            "/policy.json".to_string(),
            FixtureResponse::ok(new_policy.clone()),
        );
        routes.insert(
            "/policy.json.sig".to_string(),
            FixtureResponse::ok(new_sig.clone()),
        );
        let fixture = spawn_http_fixture(2, routes);
        let url = format!("{}/policy.json", fixture.base_url);

        run_update_for_test(&url, &pubkey_path, &policy_path)
            .expect("valid update should be installed");
        fixture.join();

        let policy_mode = std::fs::metadata(&policy_path)
            .expect("policy metadata should exist")
            .permissions()
            .mode()
            & 0o777;
        let sig_mode = std::fs::metadata(&sig_path)
            .expect("signature metadata should exist")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(policy_mode, DEFAULT_POLICY_MODE);
        assert_eq!(sig_mode, DEFAULT_POLICY_MODE);
    }

    #[test]
    fn update_success_preserves_existing_policy_and_signature_modes() {
        let temp = TempDir::new().expect("test tempdir should be created");
        let policy_path = temp.path().join("policy.json");
        let sig_path = temp.path().join("policy.json.sig");
        let pubkey_path = temp.path().join("secure_sudoers_public_key.pem");

        let signing_key = SigningKey::generate(&mut OsRng);
        write_test_public_key(&pubkey_path, &signing_key);

        std::fs::write(&policy_path, policy_json(1)).expect("seed policy should be writable");
        std::fs::write(&sig_path, vec![7u8; 64]).expect("seed signature should be writable");
        std::fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o644))
            .expect("seed policy mode should be set");
        std::fs::set_permissions(&sig_path, std::fs::Permissions::from_mode(0o640))
            .expect("seed signature mode should be set");

        let new_policy = policy_json(2);
        let new_sig = signing_key.sign(&new_policy).to_bytes().to_vec();

        let mut routes = HashMap::new();
        routes.insert(
            "/policy.json".to_string(),
            FixtureResponse::ok(new_policy.clone()),
        );
        routes.insert(
            "/policy.json.sig".to_string(),
            FixtureResponse::ok(new_sig.clone()),
        );
        let fixture = spawn_http_fixture(2, routes);
        let url = format!("{}/policy.json", fixture.base_url);

        run_update_for_test(&url, &pubkey_path, &policy_path)
            .expect("valid update should be installed");
        fixture.join();

        let updated_policy_mode =
            std::fs::metadata(&policy_path).expect("updated policy should have metadata");
        let updated_sig_mode =
            std::fs::metadata(&sig_path).expect("updated signature should have metadata");
        assert_eq!(updated_policy_mode.permissions().mode() & 0o777, 0o644);
        assert_eq!(updated_sig_mode.permissions().mode() & 0o777, 0o640);
    }

    #[test]
    fn update_rejects_downgrade_and_preserves_existing_files() {
        let temp = TempDir::new().expect("test tempdir should be created");
        let policy_path = temp.path().join("policy.json");
        let sig_path = temp.path().join("policy.json.sig");
        let pubkey_path = temp.path().join("secure_sudoers_public_key.pem");

        let signing_key = SigningKey::generate(&mut OsRng);
        write_test_public_key(&pubkey_path, &signing_key);

        let existing_policy = policy_json(9);
        let existing_sig = vec![1u8; 64];
        std::fs::write(&policy_path, &existing_policy).expect("seed policy should be writable");
        std::fs::write(&sig_path, &existing_sig).expect("seed signature should be writable");

        let downgrade_policy = policy_json(8);
        let downgrade_sig = signing_key.sign(&downgrade_policy).to_bytes().to_vec();

        let mut routes = HashMap::new();
        routes.insert(
            "/policy.json".to_string(),
            FixtureResponse::ok(downgrade_policy),
        );
        routes.insert(
            "/policy.json.sig".to_string(),
            FixtureResponse::ok(downgrade_sig),
        );
        let fixture = spawn_http_fixture(2, routes);
        let url = format!("{}/policy.json", fixture.base_url);

        let err = run_update_for_test(&url, &pubkey_path, &policy_path)
            .expect_err("downgrade should be rejected");
        fixture.join();

        match err {
            Error::Config(msg) => {
                assert!(
                    msg.contains("Downgrade rejected"),
                    "unexpected error: {msg}"
                );
            }
            other => panic!("expected downgrade config error, got: {other}"),
        }
        assert_eq!(
            std::fs::read(&policy_path).expect("policy should still be readable"),
            existing_policy
        );
        assert_eq!(
            std::fs::read(&sig_path).expect("signature should still be readable"),
            existing_sig
        );
    }

    #[test]
    fn update_rejects_oversized_response_and_preserves_existing_files() {
        let temp = TempDir::new().expect("test tempdir should be created");
        let policy_path = temp.path().join("policy.json");
        let sig_path = temp.path().join("policy.json.sig");
        let pubkey_path = temp.path().join("secure_sudoers_public_key.pem");

        let signing_key = SigningKey::generate(&mut OsRng);
        write_test_public_key(&pubkey_path, &signing_key);

        let existing_policy = policy_json(3);
        let existing_sig = vec![2u8; 64];
        std::fs::write(&policy_path, &existing_policy).expect("seed policy should be writable");
        std::fs::write(&sig_path, &existing_sig).expect("seed signature should be writable");

        let oversized_len = MAX_POLICY_BYTES + 1;
        let mut routes = HashMap::new();
        routes.insert(
            "/policy.json".to_string(),
            FixtureResponse::ok(vec![b'a'; 16]).with_content_length_override(oversized_len),
        );
        let fixture = spawn_http_fixture(1, routes);
        let url = format!("{}/policy.json", fixture.base_url);

        let err = run_update_for_test(&url, &pubkey_path, &policy_path)
            .expect_err("oversized update must fail");
        fixture.join();

        match err {
            Error::Config(msg) => {
                assert!(
                    msg.contains("exceeds") && msg.contains(&MAX_POLICY_BYTES.to_string()),
                    "unexpected oversize error: {msg}"
                );
            }
            other => panic!("expected oversize config error, got: {other}"),
        }
        assert_eq!(
            std::fs::read(&policy_path).expect("policy should still be readable"),
            existing_policy
        );
        assert_eq!(
            std::fs::read(&sig_path).expect("signature should still be readable"),
            existing_sig
        );
    }

    #[test]
    fn update_rejects_bad_signature_and_preserves_existing_files() {
        let temp = TempDir::new().expect("test tempdir should be created");
        let policy_path = temp.path().join("policy.json");
        let sig_path = temp.path().join("policy.json.sig");
        let pubkey_path = temp.path().join("secure_sudoers_public_key.pem");

        let signing_key = SigningKey::generate(&mut OsRng);
        write_test_public_key(&pubkey_path, &signing_key);

        let existing_policy = policy_json(4);
        let existing_sig = vec![3u8; 64];
        std::fs::write(&policy_path, &existing_policy).expect("seed policy should be writable");
        std::fs::write(&sig_path, &existing_sig).expect("seed signature should be writable");

        let candidate_policy = policy_json(5);
        let mut routes = HashMap::new();
        routes.insert(
            "/policy.json".to_string(),
            FixtureResponse::ok(candidate_policy),
        );
        routes.insert(
            "/policy.json.sig".to_string(),
            FixtureResponse::ok(vec![0u8; 64]),
        );
        let fixture = spawn_http_fixture(2, routes);
        let url = format!("{}/policy.json", fixture.base_url);

        let err = run_update_for_test(&url, &pubkey_path, &policy_path)
            .expect_err("bad signature must fail");
        fixture.join();

        match err {
            Error::Security(msg) => {
                assert!(
                    msg.contains("Signature verification failed"),
                    "unexpected signature error: {msg}"
                );
            }
            other => panic!("expected signature verification error, got: {other}"),
        }
        assert_eq!(
            std::fs::read(&policy_path).expect("policy should still be readable"),
            existing_policy
        );
        assert_eq!(
            std::fs::read(&sig_path).expect("signature should still be readable"),
            existing_sig
        );
    }

    #[test]
    fn update_rolls_back_signature_if_policy_replace_fails() {
        let temp = TempDir::new().expect("test tempdir should be created");
        let policy_path = temp.path().join("policy.json");
        let sig_path = temp.path().join("policy.json.sig");
        let pubkey_path = temp.path().join("secure_sudoers_public_key.pem");

        std::fs::create_dir(&policy_path).expect("policy path directory should be created");
        let existing_sig = vec![0x42, 0x99, 0x10, 0x23];
        std::fs::write(&sig_path, &existing_sig).expect("seed signature should be writable");

        let signing_key = SigningKey::generate(&mut OsRng);
        write_test_public_key(&pubkey_path, &signing_key);

        let candidate_policy = policy_json(2);
        let candidate_sig = signing_key.sign(&candidate_policy).to_bytes().to_vec();

        let mut routes = HashMap::new();
        routes.insert(
            "/policy.json".to_string(),
            FixtureResponse::ok(candidate_policy),
        );
        routes.insert(
            "/policy.json.sig".to_string(),
            FixtureResponse::ok(candidate_sig),
        );
        let fixture = spawn_http_fixture(2, routes);
        let url = format!("{}/policy.json", fixture.base_url);

        let err = run_update_for_test(&url, &pubkey_path, &policy_path)
            .expect_err("policy replace should fail against a directory target");
        fixture.join();

        match err {
            Error::IoContext(msg, _) => {
                assert!(
                    msg.contains("Atomic rename of policy failed"),
                    "unexpected policy persist error: {msg}"
                );
            }
            other => panic!("expected policy rename IO error, got: {other}"),
        }
        assert!(
            policy_path.is_dir(),
            "policy path should still be a directory"
        );
        assert_eq!(
            std::fs::read(&sig_path).expect("signature should still be readable"),
            existing_sig
        );
    }

    #[test]
    fn rollback_restores_previous_signature_on_pre_persist_policy_error() {
        let temp = TempDir::new().expect("test tempdir should be created");
        let sig_path = temp.path().join("policy.json.sig");
        let previous_sig = vec![0x01, 0x02, 0x03, 0x04];
        let new_sig = vec![0x99, 0x88, 0x77, 0x66];
        std::fs::write(&sig_path, &new_sig).expect("new signature should be writable");

        let err = run_with_signature_rollback(
            sig_path
                .to_str()
                .expect("signature path must be valid UTF-8"),
            Some(previous_sig.as_slice()),
            Some(0o644),
            false,
            || {
                Err(Error::IoContext(
                    "Failed to write temp policy file".to_string(),
                    std::io::Error::other("simulated failure"),
                ))
            },
        )
        .expect_err("simulated policy error should fail");

        match err {
            Error::IoContext(msg, _) => {
                assert!(
                    msg.contains("Failed to write temp policy file"),
                    "unexpected error: {msg}"
                );
            }
            other => panic!("expected IO-context policy error, got: {other}"),
        }
        assert_eq!(
            std::fs::read(&sig_path).expect("signature should still be readable"),
            previous_sig
        );
        let mode = std::fs::metadata(&sig_path)
            .expect("signature metadata should be available")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o644, "rollback should preserve signature mode");
    }

    #[test]
    fn rollback_removes_signature_when_no_previous_signature_exists() {
        let temp = TempDir::new().expect("test tempdir should be created");
        let sig_path = temp.path().join("policy.json.sig");
        std::fs::write(&sig_path, vec![0xaa, 0xbb, 0xcc])
            .expect("new signature should be writable");

        let err = run_with_signature_rollback(
            sig_path
                .to_str()
                .expect("signature path must be valid UTF-8"),
            None,
            None,
            false,
            || Err(Error::Config("simulated policy failure".to_string())),
        )
        .expect_err("simulated policy error should fail");

        match err {
            Error::Config(msg) => {
                assert!(
                    msg.contains("simulated policy failure"),
                    "unexpected error: {msg}"
                );
            }
            other => panic!("expected config error, got: {other}"),
        }
        assert!(
            !sig_path.exists(),
            "signature should be removed when no prior signature exists"
        );
    }
}
