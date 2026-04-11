use secure_sudoers_common::error::Error;
use std::io::Error as IoError;

pub fn drop_capabilities() -> Result<(), Error> {
    let last_cap = read_cap_last_cap()?;
    drop_bounding_capabilities_with(last_cap, |cap| {
        let ret = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
        if ret == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    })?;

    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    let header = CapHeader {
        version: 0x20080522, // _LINUX_CAPABILITY_VERSION_3
        pid: 0,
    };
    let data = [
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];

    let ret = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &header as *const CapHeader,
            &data as *const CapData,
        )
    };

    if ret != 0 {
        return Err(Error::IoContext(
            "Security failure: capset failed".to_string(),
            IoError::last_os_error(),
        ));
    }

    Ok(())
}

pub(super) fn drop_bounding_capabilities_with<F>(
    last_cap: u32,
    mut drop_one: F,
) -> Result<(), Error>
where
    F: FnMut(u32) -> Result<(), IoError>,
{
    for cap in 0..=last_cap {
        if let Err(err) = drop_one(cap) {
            tracing::error!(
                capability = cap,
                error = %err,
                "Capability bounding-set drop failed"
            );
            return Err(Error::IoContext(
                format!("Security failure: PR_CAPBSET_DROP failed for capability {cap}"),
                err,
            ));
        }
    }
    Ok(())
}

fn read_cap_last_cap() -> Result<u32, Error> {
    let cap_last_cap = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap").map_err(|e| {
        Error::IoContext(
            "Security failure: cannot read /proc/sys/kernel/cap_last_cap".to_string(),
            e,
        )
    })?;
    parse_cap_last_cap(&cap_last_cap)
}

pub(super) fn parse_cap_last_cap(value: &str) -> Result<u32, Error> {
    let trimmed = value.trim();
    trimmed.parse::<u32>().map_err(|e| {
        Error::System(format!(
            "Security failure: invalid /proc/sys/kernel/cap_last_cap value '{trimmed}': {e}"
        ))
    })
}
