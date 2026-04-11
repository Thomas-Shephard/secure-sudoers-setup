pub const INSTALL_POLICY_PATH: &str = "/etc/secure-sudoers/policy.json";
pub const INSTALL_PUBLIC_KEY_PATH: &str = "/etc/secure-sudoers/secure_sudoers_public_key.pem";
pub const INSTALL_BINARY: &str = "/usr/local/bin/secure-sudoers";
pub const INSTALL_UTILS_BINARY: &str = "/usr/local/bin/secure-sudoers-utils";
pub const INSTALL_SUDOERS_PATH: &str = "/etc/sudoers.d/secure-sudoers";
pub const ENTRY_POINT_DIR: &str = "/usr/local/bin";

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
