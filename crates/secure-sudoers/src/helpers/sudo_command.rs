use std::path::Path;

pub(super) fn basename(token: &str) -> &str {
    Path::new(token)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(token)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SudoCommandTokenError {
    InvalidPrefix,
    MissingDelegatedCommand,
}

pub(super) fn delegated_command_token_from_sudo_command(
    sudo_cmd: &str,
) -> Result<String, SudoCommandTokenError> {
    let first_tokens = split_sudo_command_prefix_tokens(sudo_cmd, 1)
        .ok_or(SudoCommandTokenError::InvalidPrefix)?;
    let first_token = first_tokens.first().map(String::as_str).unwrap_or("");
    let first_name = basename(first_token);

    if (first_name == "secure-sudoers" || first_name == "secure_sudoers") && !first_token.is_empty()
    {
        let tokens = split_sudo_command_prefix_tokens(sudo_cmd, 2)
            .ok_or(SudoCommandTokenError::InvalidPrefix)?;
        tokens
            .get(1)
            .cloned()
            .ok_or(SudoCommandTokenError::MissingDelegatedCommand)
    } else {
        Ok(first_token.to_string())
    }
}

pub(super) fn split_sudo_command_prefix_tokens(s: &str, max_tokens: usize) -> Option<Vec<String>> {
    if max_tokens == 0 {
        return Some(Vec::new());
    }

    let mut chars = s.chars().peekable();
    let mut tokens = Vec::new();
    while tokens.len() < max_tokens {
        while matches!(chars.peek(), Some(ch) if ch.is_whitespace()) {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }

        let mut token = String::new();
        let mut quote: Option<char> = None;
        let mut escaped = false;

        for ch in chars.by_ref() {
            if escaped {
                token.push(ch);
                escaped = false;
                continue;
            }

            if ch == '\\' && quote != Some('\'') {
                escaped = true;
                continue;
            }

            if let Some(q) = quote {
                if ch == q {
                    quote = None;
                } else {
                    token.push(ch);
                }
                continue;
            }

            if ch == '\'' || ch == '"' {
                quote = Some(ch);
                continue;
            }

            if ch.is_whitespace() {
                break;
            }

            token.push(ch);
        }

        if escaped || quote.is_some() {
            return None;
        }

        tokens.push(token);
    }

    Some(tokens)
}
