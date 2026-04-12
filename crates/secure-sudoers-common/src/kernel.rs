use crate::error::Error;
use std::mem::MaybeUninit;

pub const MIN_SUPPORTED_KERNEL_MAJOR: u32 = 4;
pub const MIN_SUPPORTED_KERNEL_MINOR: u32 = 19;

#[cfg(any(test, debug_assertions))]
const TEST_KERNEL_RELEASE_ENV: &str = "SECURE_SUDOERS_TEST_KERNEL_RELEASE";

pub fn ensure_minimum_kernel_version() -> Result<(), Error> {
    let release = current_kernel_release()?;
    ensure_minimum_kernel_version_for_release(&release)
}

pub fn ensure_minimum_kernel_version_for_release(release: &str) -> Result<(), Error> {
    let (major, minor) = parse_kernel_release(release)?;
    if major > MIN_SUPPORTED_KERNEL_MAJOR
        || (major == MIN_SUPPORTED_KERNEL_MAJOR && minor >= MIN_SUPPORTED_KERNEL_MINOR)
    {
        return Ok(());
    }

    Err(Error::System(format!(
        "Unsupported Linux kernel release '{release}': secure-sudoers requires Linux kernel {}.{} or newer.",
        MIN_SUPPORTED_KERNEL_MAJOR, MIN_SUPPORTED_KERNEL_MINOR
    )))
}

pub fn parse_kernel_release(release: &str) -> Result<(u32, u32), Error> {
    let trimmed = release.trim();
    if trimmed.is_empty() {
        return Err(Error::Parse("Kernel release is empty".to_string()));
    }

    let mut parts = trimmed.split('.');
    let major = parse_component(parts.next(), "major", trimmed)?;
    let minor = parse_component(parts.next(), "minor", trimmed)?;
    Ok((major, minor))
}

fn parse_component(component: Option<&str>, label: &str, release: &str) -> Result<u32, Error> {
    let component = component.ok_or_else(|| {
        Error::Parse(format!(
            "Invalid Linux kernel release '{release}': missing {label} component"
        ))
    })?;
    let end = component
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(component.len());
    let digits = &component[..end];
    if digits.is_empty() {
        return Err(Error::Parse(format!(
            "Invalid Linux kernel release '{release}': malformed {label} component '{component}'"
        )));
    }

    digits.parse::<u32>().map_err(|e| {
        Error::Parse(format!(
            "Invalid Linux kernel release '{release}': cannot parse {label} component '{component}': {e}"
        ))
    })
}

fn current_kernel_release() -> Result<String, Error> {
    #[cfg(any(test, debug_assertions))]
    if let Ok(release_override) = std::env::var(TEST_KERNEL_RELEASE_ENV) {
        return Ok(release_override);
    }

    let mut uts = MaybeUninit::<libc::utsname>::zeroed();
    if unsafe { libc::uname(uts.as_mut_ptr()) } != 0 {
        return Err(Error::IoContext(
            "Failed to query Linux kernel release with uname(2)".to_string(),
            std::io::Error::last_os_error(),
        ));
    }

    let uts = unsafe { uts.assume_init() };
    let release_bytes: Vec<u8> = uts
        .release
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    let release = std::str::from_utf8(&release_bytes).map_err(|e| {
        Error::Parse(format!(
            "Kernel release from uname(2) is not valid UTF-8: {e}"
        ))
    })?;
    Ok(release.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kernel_release_accepts_standard_format() {
        assert_eq!(parse_kernel_release("4.19.0").unwrap(), (4, 19));
    }

    #[test]
    fn parse_kernel_release_accepts_distro_suffixes() {
        assert_eq!(parse_kernel_release("5.15.0-1092-azure").unwrap(), (5, 15));
        assert_eq!(parse_kernel_release("4.19-200").unwrap(), (4, 19));
    }

    #[test]
    fn parse_kernel_release_rejects_invalid_strings() {
        let missing_minor = parse_kernel_release("4").unwrap_err();
        assert!(
            missing_minor
                .to_string()
                .contains("missing minor component"),
            "{missing_minor}"
        );

        let malformed_major = parse_kernel_release("x.19.0").unwrap_err();
        assert!(
            malformed_major
                .to_string()
                .contains("malformed major component"),
            "{malformed_major}"
        );
    }

    #[test]
    fn ensure_minimum_kernel_version_accepts_4_19_and_newer() {
        assert!(ensure_minimum_kernel_version_for_release("4.19.0").is_ok());
        assert!(ensure_minimum_kernel_version_for_release("6.8.12").is_ok());
    }

    #[test]
    fn ensure_minimum_kernel_version_rejects_older_releases() {
        let err = ensure_minimum_kernel_version_for_release("4.18.20")
            .expect_err("kernel release 4.18 must be rejected");
        assert!(
            err.to_string()
                .contains("requires Linux kernel 4.19 or newer"),
            "{err}"
        );
    }
}
