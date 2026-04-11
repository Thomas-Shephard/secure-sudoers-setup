const CHATTR_CANDIDATE_PATHS: [&str; 3] = ["/usr/bin/chattr", "/bin/chattr", "/usr/sbin/chattr"];

pub(super) fn find_first_existing_path<'a>(candidates: &'a [&'a str]) -> Option<&'a str> {
    candidates
        .iter()
        .copied()
        .find(|path| std::path::Path::new(path).exists())
}

pub(super) fn should_skip_chattr_target(flag: &str, path: &str) -> Result<bool, std::io::Error> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(flag == "-i"),
        Err(e) => Err(e),
    }
}

pub(crate) fn chattr_op(flag: &str, paths: &[&str]) -> Vec<String> {
    if paths.is_empty() {
        return Vec::new();
    }

    let Some(chattr_path) = find_first_existing_path(&CHATTR_CANDIDATE_PATHS) else {
        return vec![format!(
            "Cannot execute chattr from known paths ({})",
            CHATTR_CANDIDATE_PATHS.join(", ")
        )];
    };
    let mut errors = Vec::new();
    for path in paths {
        let skip = match should_skip_chattr_target(flag, path) {
            Ok(skip) => skip,
            Err(e) => {
                errors.push(format!(
                    "Cannot inspect {path} before chattr operation {flag}: {e}"
                ));
                continue;
            }
        };
        if skip {
            continue;
        }

        let command_display = format!("{chattr_path} {flag} -- {path}");
        match std::process::Command::new(chattr_path)
            .arg(flag)
            .arg("--")
            .arg(path)
            .status()
        {
            Ok(s) if s.success() => {}
            Ok(s) => errors.push(format!("{command_display}: exited with {s}")),
            Err(e) => errors.push(format!("{command_display}: {e}")),
        }
    }
    errors
}
