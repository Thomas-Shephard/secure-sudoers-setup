use secure_sudoers_common::models::{
    ParameterConfig, ParameterType, SecureSudoersPolicy, UnauthorizedAuditMode,
};
use std::collections::HashMap;

fn is_known_flag_argument(arg: &str, parameters: &HashMap<String, ParameterConfig>) -> bool {
    if arg.starts_with("--") {
        if let Some(idx) = arg.find('=') {
            return parameters.contains_key(&arg[..idx]);
        }
        return parameters.contains_key(arg);
    }

    if !arg.starts_with('-') || arg == "-" {
        return false;
    }

    if parameters.contains_key(arg) {
        return true;
    }

    for c in arg[1..].chars() {
        let short_flag = format!("-{c}");
        let Some(config) = parameters.get(&short_flag) else {
            return false;
        };

        if config.param_type != ParameterType::Bool {
            return true;
        }
    }

    true
}

pub fn redact_args(args: &[String], policy: &SecureSudoersPolicy, tool_name: &str) -> Vec<String> {
    if let Some(tool) = policy.tools.get(tool_name) {
        let mut redacted = Vec::with_capacity(args.len());
        let mut skip_next = false;
        let mut after_double_dash = false;
        for arg in args {
            if skip_next {
                redacted.push("[REDACTED]".to_string());
                skip_next = false;
                continue;
            }

            if arg == "--" {
                redacted.push(arg.clone());
                after_double_dash = true;
                continue;
            }

            if after_double_dash
                && let Some(ref pos_config) = tool.positional
                && pos_config.sensitive
            {
                redacted.push("[REDACTED]".to_string());
                continue;
            }

            if let Some(idx) = arg.find('=') {
                let key = &arg[..idx];
                if let Some(config) = tool.parameters.get(key)
                    && config.sensitive
                {
                    redacted.push(format!("{}=[REDACTED]", key));
                    continue;
                }
            }

            let mut attached_found = false;
            for (f_name, config) in &tool.parameters {
                if config.sensitive
                    && f_name.starts_with('-')
                    && !f_name.starts_with("--")
                    && f_name.len() == 2
                {
                    let flag_char = f_name.chars().nth(1).unwrap();
                    if arg.starts_with('-')
                        && !arg.starts_with("--")
                        && let Some(pos) = arg.find(flag_char)
                    {
                        if pos < arg.len() - 1 {
                            // For attached short-flag payloads, redact the tail conservatively.
                            redacted.push(format!("{}[REDACTED]", &arg[..pos + 1]));
                        } else {
                            redacted.push(arg.clone());
                            skip_next = true;
                        }
                        attached_found = true;
                        break;
                    }
                }
            }
            if attached_found {
                continue;
            }

            if let Some(config) = tool.parameters.get(arg)
                && config.sensitive
            {
                redacted.push(arg.clone());
                skip_next = true;
            } else if !after_double_dash && arg.starts_with("--") {
                if let Some(idx) = arg.find('=') {
                    let key = &arg[..idx];
                    if !tool.parameters.contains_key(key) {
                        redacted.push(format!("{key}=[REDACTED]"));
                        continue;
                    }
                } else if !tool.parameters.contains_key(arg) {
                    redacted.push(arg.clone());
                    skip_next = true;
                    continue;
                }
            } else if let Some(ref pos_config) = tool.positional
                && pos_config.sensitive
            {
                if arg.starts_with('-') && is_known_flag_argument(arg, &tool.parameters) {
                    redacted.push(arg.clone());
                } else {
                    redacted.push("[REDACTED]".to_string());
                }
            } else {
                redacted.push(arg.clone());
            }
        }
        redacted
    } else {
        match policy.global_settings.unauthorized_audit_mode {
            UnauthorizedAuditMode::Minimal => {
                vec![format!("[{} arguments suppressed]", args.len())]
            }
            UnauthorizedAuditMode::KeysOnly => args
                .iter()
                .map(|arg| {
                    if let Some(idx) = arg.find('=') {
                        let key = &arg[..idx];
                        if key.starts_with('-') {
                            return format!("{}=[REDACTED]", key);
                        }
                    } else if arg.starts_with('-') {
                        if !arg.starts_with("--") && arg.len() > 2 {
                            return format!("{}[REDACTED]", &arg[..2]);
                        }
                        return arg.clone();
                    }
                    "[REDACTED]".to_string()
                })
                .collect(),
            UnauthorizedAuditMode::Full => args.to_vec(),
        }
    }
}
