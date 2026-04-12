use crate::error::Error;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::sync::OnceLock;

pub struct SecurePath {
    pub path: String,
    pub fd: OwnedFd,
}

impl PartialEq for SecurePath {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl PartialEq<str> for SecurePath {
    fn eq(&self, other: &str) -> bool {
        self.path == other
    }
}

impl PartialEq<&str> for SecurePath {
    fn eq(&self, other: &&str) -> bool {
        self.path == *other
    }
}

impl PartialEq<String> for SecurePath {
    fn eq(&self, other: &String) -> bool {
        self.path == *other
    }
}

impl SecurePath {
    #[cfg(any(test, feature = "testing"))]
    pub fn new_for_testing(path: &str, fd: OwnedFd) -> Self {
        Self {
            path: path.to_string(),
            fd,
        }
    }
}

impl std::fmt::Debug for SecurePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurePath")
            .field("path", &self.path)
            .field("fd", &self.fd)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ParameterType {
    Bool,
    String,
    Path,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParameterConfig {
    #[serde(rename = "type")]
    pub param_type: ParameterType,
    #[serde(default)]
    pub sensitive: bool,
    pub regex: Option<String>,
    #[serde(skip)]
    pub compiled_regex: Option<regex::Regex>,
    pub allowed: Option<Vec<String>>,
    pub disallowed: Option<Vec<String>>,
    pub help: Option<String>,
}

impl ParameterConfig {
    pub(crate) fn is_explicitly_disallowed(&self, val: &str) -> bool {
        if let Some(ref disallowed) = self.disallowed {
            disallowed.iter().any(|entry| entry == val)
        } else {
            false
        }
    }

    pub(crate) fn matches_allowed_or_regex(&self, val: &str) -> bool {
        let allowed_match = self
            .allowed
            .as_ref()
            .map(|allowed| allowed.iter().any(|entry| entry == val));
        let regex_match = self.regex.as_ref().map(|_| {
            self.compiled_regex
                .as_ref()
                .is_some_and(|re| re.is_match(val))
        });

        match (allowed_match, regex_match) {
            (Some(allowed), Some(regex)) => allowed || regex,
            (Some(allowed), None) => allowed,
            (None, Some(regex)) => regex,
            (None, None) => true,
        }
    }

    pub fn matches(&self, val: &str) -> bool {
        if self.is_explicitly_disallowed(val) {
            return false;
        }
        self.matches_allowed_or_regex(val)
    }

    pub fn any(t: ParameterType) -> Self {
        Self {
            param_type: t,
            sensitive: false,
            regex: None,
            compiled_regex: None,
            allowed: None,
            disallowed: None,
            help: None,
        }
    }

    pub fn bool() -> Self {
        Self::any(ParameterType::Bool)
    }

    pub fn string() -> Self {
        Self::any(ParameterType::String)
    }

    pub fn path() -> Self {
        Self::any(ParameterType::Path)
    }

    pub fn sensitive(mut self) -> Self {
        self.sensitive = true;
        self
    }

    pub fn regex(mut self, r: String) -> Self {
        self.compiled_regex = regex::Regex::new(&r).ok();
        self.regex = Some(r);
        self
    }

    pub fn allowed(mut self, entries: Vec<String>) -> Self {
        self.allowed = Some(entries);
        self
    }

    pub fn disallowed(mut self, values: Vec<String>) -> Self {
        self.disallowed = Some(values);
        self
    }
}

fn default_unshare_ipc() -> bool {
    true
}
fn default_unshare_uts() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationSettings {
    #[serde(default)]
    pub unshare_network: bool,
    #[serde(default)]
    pub unshare_pid: bool,
    #[serde(default = "default_unshare_ipc")]
    pub unshare_ipc: bool,
    #[serde(default = "default_unshare_uts")]
    pub unshare_uts: bool,
    #[serde(default)]
    pub private_mounts: Vec<String>,
    #[serde(default)]
    pub readonly_mounts: Vec<String>,
}

impl Default for IsolationSettings {
    fn default() -> Self {
        IsolationSettings {
            unshare_network: false,
            unshare_pid: false,
            unshare_ipc: true,
            unshare_uts: true,
            private_mounts: Vec::new(),
            readonly_mounts: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPolicy {
    #[serde(default)]
    pub id: Option<String>,
    pub real_binary: String,
    #[serde(default)]
    pub verbs: Vec<String>,
    #[serde(default)]
    pub parameters: HashMap<String, ParameterConfig>,
    pub positional: Option<ParameterConfig>,
    pub help_description: String,
    pub isolation: Option<IsolationSettings>,
    #[serde(default)]
    pub env_whitelist: Vec<String>,
}

fn default_log_destination() -> String {
    "syslog".to_string()
}
fn default_log_format() -> String {
    "text".to_string()
}
fn default_admin_contact() -> String {
    "Please contact your administrator.".to_string()
}
fn default_safe_arg_regex() -> String {
    r"^[a-zA-Z0-9._+\-=:,@/]+$".to_string()
}
fn default_common_env_whitelist() -> Vec<String> {
    vec![
        "TERM".to_string(),
        "LANG".to_string(),
        "LC_ALL".to_string(),
        "LS_COLORS".to_string(),
    ]
}
fn default_blocked_paths() -> Vec<String> {
    vec![
        "/etc/shadow".to_string(),
        "/etc/gshadow".to_string(),
        "/etc/sudoers".to_string(),
        "/etc/secure-sudoers".to_string(),
        "/etc/ssh".to_string(),
        "/etc/pam.d".to_string(),
        "/root".to_string(),
        "/dev/mem".to_string(),
        "/dev/kmem".to_string(),
        "/dev/port".to_string(),
        "/proc/kcore".to_string(),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum UnauthorizedAuditMode {
    #[default]
    Minimal,
    KeysOnly,
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalSettings {
    #[serde(default = "default_log_destination")]
    pub log_destination: String,
    #[serde(default = "default_log_format")]
    pub log_format: String,
    #[serde(default = "default_admin_contact")]
    pub admin_contact: String,
    #[serde(default = "default_safe_arg_regex")]
    pub safe_arg_regex: String,
    #[serde(default = "default_common_env_whitelist")]
    pub common_env_whitelist: Vec<String>,
    #[serde(default = "default_blocked_paths")]
    pub blocked_paths: Vec<String>,
    #[serde(default)]
    pub unauthorized_audit_mode: UnauthorizedAuditMode,
    pub default_isolation: Option<IsolationSettings>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecureSudoersPolicy {
    pub version: String,
    #[serde(default)]
    pub serial: i32,
    pub global_settings: GlobalSettings,
    pub tools: HashMap<String, ToolPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationContext {
    Positional,
    DelimitedPositional,
    Flag(String),
}

impl std::fmt::Display for ValidationContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationContext::Positional => write!(f, "positional"),
            ValidationContext::DelimitedPositional => write!(f, "delimited positional"),
            ValidationContext::Flag(s) => write!(f, "flag '{}'", s),
        }
    }
}

static TOOL_NAME_REGEX: OnceLock<regex::Regex> = OnceLock::new();

pub fn is_valid_tool_name(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." {
        return false;
    }

    TOOL_NAME_REGEX
        .get_or_init(|| {
            regex::Regex::new(r"^[a-zA-Z0-9._+-]+$").expect("tool-name regex literal must compile")
        })
        .is_match(name)
}

fn canonicalize_path_list_entries(
    entries: &mut Vec<String>,
    list_name: &str,
    tool_name: &str,
    config_label: &str,
) -> Result<(), Error> {
    let mut canonicalized = Vec::with_capacity(entries.len());
    for entry in entries.iter() {
        let path = std::path::Path::new(entry);
        if !path.is_absolute() {
            return Err(Error::Config(format!(
                "{} entry '{}' for {} in tool '{}' must be an absolute path",
                list_name, entry, config_label, tool_name
            )));
        }

        match std::fs::canonicalize(path) {
            Ok(path) => canonicalized.push(path.to_string_lossy().into_owned()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => canonicalized.push(entry.clone()),
            Err(e) => {
                return Err(Error::IoContext(
                    format!(
                        "Security failure: cannot canonicalize {} path '{}' for {} in tool '{}'",
                        list_name, entry, config_label, tool_name
                    ),
                    e,
                ));
            }
        }
    }
    *entries = canonicalized;
    Ok(())
}

fn canonicalize_path_list_config_entries(
    config: &mut ParameterConfig,
    tool_name: &str,
    config_label: &str,
) -> Result<(), Error> {
    if config.param_type != ParameterType::Path {
        return Ok(());
    }

    if let Some(allowed) = config.allowed.as_mut() {
        canonicalize_path_list_entries(allowed, "allowed", tool_name, config_label)?;
    }

    if let Some(disallowed) = config.disallowed.as_mut() {
        canonicalize_path_list_entries(disallowed, "disallowed", tool_name, config_label)?;
    }

    Ok(())
}

fn compile_parameter_regex(
    config: &mut ParameterConfig,
    tool_name: &str,
    config_label: &str,
) -> Result<(), Error> {
    if let Some(regex_str) = config.regex.as_ref() {
        let compiled = regex::Regex::new(regex_str).map_err(|_| {
            Error::Parse(format!(
                "Invalid regex '{}' in {} for tool '{}'",
                regex_str, config_label, tool_name
            ))
        })?;
        config.compiled_regex = Some(compiled);
    } else {
        config.compiled_regex = None;
    }

    Ok(())
}

impl SecureSudoersPolicy {
    pub fn validate(&mut self) -> Result<(), Error> {
        if regex::Regex::new(&self.global_settings.safe_arg_regex).is_err() {
            return Err(Error::Parse("Invalid regex in safe_arg_regex".into()));
        }

        let mut canonicalized_blocked = Vec::new();
        for path in &self.global_settings.blocked_paths {
            if !path.starts_with('/') {
                return Err(Error::Config(format!(
                    "Blocked path must be absolute: {}",
                    path
                )));
            }
            match std::fs::canonicalize(path) {
                Ok(p) => canonicalized_blocked.push(p.to_string_lossy().into_owned()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    canonicalized_blocked.push(path.clone());
                }
                Err(e) => {
                    return Err(Error::IoContext(
                        format!(
                            "Security failure: cannot canonicalize blocked path '{}'",
                            path
                        ),
                        e,
                    ));
                }
            }
        }
        self.global_settings.blocked_paths = canonicalized_blocked;

        for (name, tool) in &mut self.tools {
            if !is_valid_tool_name(name) {
                return Err(Error::Validation(format!(
                    "Invalid tool name in policy: '{}'",
                    name
                )));
            }
            if !tool.real_binary.starts_with('/') {
                return Err(Error::Config(format!(
                    "real_binary for tool '{}' must be an absolute path",
                    name
                )));
            }
            for (flag, config) in &mut tool.parameters {
                compile_parameter_regex(config, name, &format!("parameter '{}'", flag))?;
                canonicalize_path_list_config_entries(
                    config,
                    name,
                    &format!("parameter '{}'", flag),
                )?;
            }
            if let Some(ref mut pos_config) = tool.positional {
                compile_parameter_regex(pos_config, name, "positional config")?;
                canonicalize_path_list_config_entries(pos_config, name, "positional config")?;
            }
        }
        Ok(())
    }

    pub fn lint(&mut self) -> Vec<String> {
        let mut results = Vec::new();

        if let Err(e) = self.validate() {
            results.push(format!("Validation failed: {}", e));
            return results;
        }

        for (name, tool) in &self.tools {
            let path = std::path::Path::new(&tool.real_binary);
            match std::fs::metadata(path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    results.push(format!(
                        "Tool '{}': real_binary '{}' does not exist on the filesystem",
                        name, tool.real_binary
                    ));
                }
                Err(e) => {
                    results.push(format!(
                        "Tool '{}': cannot inspect real_binary '{}': {}",
                        name, tool.real_binary, e
                    ));
                }
                Ok(metadata) if !metadata.is_file() => {
                    results.push(format!(
                        "Tool '{}': real_binary '{}' exists but is not a file",
                        name, tool.real_binary
                    ));
                }
                Ok(metadata) => {
                    if metadata.permissions().mode() & 0o111 == 0 {
                        results.push(format!(
                            "Tool '{}': real_binary '{}' exists but is not executable",
                            name, tool.real_binary
                        ));
                    }
                }
            }
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn test_unknown_field_in_policy_rejected() {
        let json = r#"{ "version": "1.0", "global_settings": {}, "tools": {}, "surprise": "X" }"#;
        assert!(serde_json::from_str::<SecureSudoersPolicy>(json).is_err());
    }

    #[test]
    fn test_typo_in_isolation_settings_rejected() {
        let json = r#"{ "version": "1.0", "global_settings": {}, "tools": { "apt": { "real_binary": "/usr/bin/apt", "help_description": "x", "isolation": { "unshare_netwrk": true } } } }"#;
        assert!(serde_json::from_str::<SecureSudoersPolicy>(json).is_err());
    }

    #[test]
    fn test_is_valid_tool_name() {
        assert!(is_valid_tool_name("apt"));
        assert!(is_valid_tool_name("docker-compose"));
        assert!(is_valid_tool_name("my_tool"));
        assert!(is_valid_tool_name("tool123"));
        assert!(is_valid_tool_name("a"));
        assert!(is_valid_tool_name("g++"));

        assert!(!is_valid_tool_name(""), "empty string should be invalid");
        assert!(!is_valid_tool_name("."), ". should be invalid");
        assert!(!is_valid_tool_name(".."), ".. should be invalid");
        assert!(!is_valid_tool_name("my/tool"), "slash should be invalid");
        assert!(
            !is_valid_tool_name("tool\0name"),
            "null byte should be invalid"
        );
        assert!(!is_valid_tool_name("tool,name"), "comma should be invalid");
        assert!(!is_valid_tool_name("tool name"), "space should be invalid");
        assert!(!is_valid_tool_name("tool\ttab"), "tab should be invalid");
        assert!(
            !is_valid_tool_name("tool\nnewline"),
            "newline should be invalid"
        );

        assert!(!is_valid_tool_name("tool*"));
        assert!(!is_valid_tool_name("tool?"));
        assert!(!is_valid_tool_name("tool["));
        assert!(!is_valid_tool_name("tool]"));
    }

    #[test]
    fn test_parameter_config_matches_allowed() {
        let config = ParameterConfig {
            param_type: ParameterType::String,
            sensitive: false,
            regex: None,
            compiled_regex: None,
            allowed: Some(vec!["prod".into(), "stage".into()]),
            disallowed: None,
            help: None,
        };
        assert!(config.matches("prod"));
        assert!(config.matches("stage"));
        assert!(!config.matches("dev"));
    }

    #[test]
    fn test_parameter_config_disallowed_overrides_allowed() {
        let config = ParameterConfig {
            param_type: ParameterType::String,
            sensitive: false,
            regex: None,
            compiled_regex: None,
            allowed: Some(vec!["prod".into()]),
            disallowed: Some(vec!["prod".into()]),
            help: None,
        };
        assert!(!config.matches("prod"));
    }

    #[test]
    fn test_parameter_config_matches_regex() {
        let config = ParameterConfig {
            param_type: ParameterType::String,
            sensitive: false,
            regex: Some(r"^\d+$".into()),
            compiled_regex: Some(regex::Regex::new(r"^\d+$").unwrap()),
            allowed: None,
            disallowed: None,
            help: None,
        };
        assert!(config.matches("123"));
        assert!(!config.matches("abc"));
    }

    use crate::testing::fixtures::{make_tool, make_valid_policy};

    #[test]
    fn test_policy_validate_ok() {
        let mut p = make_valid_policy();
        assert!(
            p.validate().is_ok(),
            "baseline valid policy must pass validation"
        );
    }

    #[test]
    fn test_policy_validate_invalid_safe_arg_regex() {
        let mut p = make_valid_policy();
        p.global_settings.safe_arg_regex = "[unclosed bracket".to_string();
        let err = p.validate().unwrap_err();
        assert!(
            err.to_string().contains("Invalid regex in safe_arg_regex"),
            "got: {err}"
        );
    }

    #[test]
    fn test_policy_validate_relative_blocked_path() {
        let mut p = make_valid_policy();
        p.global_settings.blocked_paths = vec!["etc/shadow".to_string()];
        let err = p.validate().unwrap_err();
        assert!(
            err.to_string().contains("Blocked path must be absolute"),
            "got: {err}"
        );
    }

    #[test]
    fn test_policy_validate_invalid_tool_name() {
        let mut p = make_valid_policy();
        p.tools
            .insert("bad/name".to_string(), make_tool("/usr/bin/tool"));
        let err = p.validate().unwrap_err();
        assert!(err.to_string().contains("Invalid tool name"), "got: {err}");
    }

    #[test]
    fn test_policy_validate_relative_real_binary() {
        let mut p = make_valid_policy();
        p.tools.insert("mytool".to_string(), make_tool("bin/ls"));
        let err = p.validate().unwrap_err();
        assert!(
            err.to_string().contains("must be an absolute path"),
            "got: {err}"
        );
    }

    #[test]
    fn test_policy_validate_invalid_parameter_regex() {
        let mut p = make_valid_policy();
        let mut tool = make_tool("/usr/bin/tool");
        tool.parameters.insert(
            "--format".to_string(),
            ParameterConfig {
                param_type: ParameterType::String,
                sensitive: false,
                regex: Some("[unclosed".to_string()),
                compiled_regex: None,
                allowed: None,
                disallowed: None,
                help: None,
            },
        );
        p.tools.insert("mytool".to_string(), tool);
        let err = p.validate().unwrap_err();
        assert!(err.to_string().contains("Invalid regex"), "got: {err}");
    }

    #[test]
    fn test_policy_validate_relative_disallowed_positional_path_for_path_tool() {
        let mut p = make_valid_policy();
        let mut tool = make_tool("/usr/bin/tool");
        tool.positional =
            Some(ParameterConfig::path().disallowed(vec!["relative/path".to_string()]));
        p.tools.insert("mytool".to_string(), tool);

        let err = p.validate().unwrap_err();
        assert!(
            err.to_string().contains("must be an absolute path"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_policy_validate_non_path_tool_allows_relative_disallowed_positional() {
        let mut p = make_valid_policy();
        let mut tool = make_tool("/usr/bin/tool");
        tool.positional =
            Some(ParameterConfig::string().disallowed(vec!["relative/path".to_string()]));
        p.tools.insert("mytool".to_string(), tool);

        assert!(p.validate().is_ok(), "unexpected validation failure");
    }

    #[test]
    fn test_policy_validate_disallowed_positional_path_canonicalization_symlink_loop_error() {
        let mut p = make_valid_policy();
        let tmp = tempfile::tempdir().unwrap();
        let loop_a = tmp.path().join("loop_a");
        let loop_b = tmp.path().join("loop_b");
        std::os::unix::fs::symlink(&loop_b, &loop_a).unwrap();
        std::os::unix::fs::symlink(&loop_a, &loop_b).unwrap();

        let mut tool = make_tool("/usr/bin/tool");
        tool.positional =
            Some(ParameterConfig::path().disallowed(vec![loop_a.to_string_lossy().into_owned()]));
        p.tools.insert("mytool".to_string(), tool);

        let err = p.validate().unwrap_err();
        assert!(
            err.to_string().contains("cannot canonicalize"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_policy_validate_canonicalizes_disallowed_path_parameter_entries() {
        let mut p = make_valid_policy();
        let tmp = tempfile::tempdir().unwrap();
        let real_file = tmp.path().join("real");
        let symlink_file = tmp.path().join("link");

        std::fs::write(&real_file, "x").unwrap();
        std::os::unix::fs::symlink(&real_file, &symlink_file).unwrap();

        let mut tool = make_tool("/usr/bin/tool");
        tool.parameters.insert(
            "--file".to_string(),
            ParameterConfig::path().disallowed(vec![symlink_file.to_string_lossy().into_owned()]),
        );
        p.tools.insert("mytool".to_string(), tool);

        p.validate().unwrap();
        let canonical = std::fs::canonicalize(&real_file)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let cfg = p
            .tools
            .get("mytool")
            .unwrap()
            .parameters
            .get("--file")
            .unwrap();
        assert_eq!(cfg.disallowed.as_ref().unwrap(), &vec![canonical]);
    }

    #[test]
    fn test_policy_validate_parameter_disallowed_path_requires_absolute() {
        let mut p = make_valid_policy();
        let mut tool = make_tool("/usr/bin/tool");
        tool.parameters.insert(
            "--file".to_string(),
            ParameterConfig::path().disallowed(vec!["relative/path".to_string()]),
        );
        p.tools.insert("mytool".to_string(), tool);

        let err = p.validate().unwrap_err();
        assert!(
            err.to_string().contains("must be an absolute path"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_policy_validate_canonicalizes_path_parameter_allowed_entries() {
        let mut p = make_valid_policy();
        let tmp = tempfile::tempdir().unwrap();
        let real_file = tmp.path().join("real_allowed");
        let symlink_file = tmp.path().join("link_allowed");

        std::fs::write(&real_file, "x").unwrap();
        std::os::unix::fs::symlink(&real_file, &symlink_file).unwrap();

        let mut tool = make_tool("/usr/bin/tool");
        tool.parameters.insert(
            "--file".to_string(),
            ParameterConfig::path().allowed(vec![symlink_file.to_string_lossy().into_owned()]),
        );
        p.tools.insert("mytool".to_string(), tool);

        p.validate().unwrap();
        let canonical = std::fs::canonicalize(&real_file)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let cfg = p
            .tools
            .get("mytool")
            .unwrap()
            .parameters
            .get("--file")
            .unwrap();
        assert_eq!(cfg.allowed.as_ref().unwrap(), &vec![canonical]);
    }

    #[test]
    fn test_policy_validate_path_parameter_allowed_require_absolute() {
        let mut p = make_valid_policy();
        let mut tool = make_tool("/usr/bin/tool");
        tool.parameters.insert(
            "--file".to_string(),
            ParameterConfig::path().allowed(vec!["relative/path".to_string()]),
        );
        p.tools.insert("mytool".to_string(), tool);

        let err = p.validate().unwrap_err();
        assert!(
            err.to_string().contains("must be an absolute path"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_policy_validate_compiles_parameter_regex_cache() {
        let mut p = make_valid_policy();
        let mut tool = make_tool("/usr/bin/tool");
        tool.parameters.insert(
            "--format".to_string(),
            ParameterConfig::string().regex(r"^prod$".to_string()),
        );
        p.tools.insert("mytool".to_string(), tool);

        p.validate().unwrap();
        let cfg = p
            .tools
            .get("mytool")
            .unwrap()
            .parameters
            .get("--format")
            .unwrap();
        assert!(cfg.compiled_regex.is_some());
    }

    #[test]
    fn test_matches_allowed_or_regex_uses_cached_compiled_regex() {
        let mut config = ParameterConfig::string().regex(r"^\d+$".to_string());
        config.compiled_regex = Some(regex::Regex::new("^NOT_A_NUMBER$").unwrap());
        assert!(!config.matches_allowed_or_regex("123"));
    }

    #[test]
    fn test_parameter_config_matches_allowed_or_regex_semantics() {
        let config = ParameterConfig::string()
            .allowed(vec!["prod".to_string()])
            .regex("^staging$".to_string());

        assert!(config.matches_allowed_or_regex("prod"));
        assert!(config.matches_allowed_or_regex("staging"));
        assert!(!config.matches_allowed_or_regex("dev"));
    }

    #[test]
    fn test_policy_lint_reports_missing_binary_with_single_metadata_pass() {
        let mut policy = make_valid_policy();
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");

        policy
            .tools
            .insert("missing".to_string(), make_tool(missing.to_str().unwrap()));

        let issues = policy.lint();
        assert!(
            issues
                .iter()
                .any(|issue| issue.contains("does not exist on the filesystem")),
            "unexpected lint output: {issues:?}"
        );
    }

    #[test]
    fn test_policy_lint_reports_non_executable_binary_with_single_metadata_pass() {
        let mut policy = make_valid_policy();
        let tmp = tempfile::tempdir().unwrap();
        let binary_path = tmp.path().join("tool.sh");

        std::fs::write(&binary_path, "#!/bin/sh\necho hi\n").unwrap();
        let mut perms = std::fs::metadata(&binary_path).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&binary_path, perms).unwrap();

        policy
            .tools
            .insert("tool".to_string(), make_tool(binary_path.to_str().unwrap()));

        let issues = policy.lint();
        assert!(
            issues
                .iter()
                .any(|issue| issue.contains("exists but is not executable")),
            "unexpected lint output: {issues:?}"
        );
    }
}
