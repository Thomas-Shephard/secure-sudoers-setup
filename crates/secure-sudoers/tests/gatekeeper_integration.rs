use secure_sudoers::helpers::invocation::parse_invocation;

#[test]
fn test_invocation_mapping() {
    let args = vec![
        "secure-sudoers".to_string(),
        "apt".to_string(),
        "update".to_string(),
    ];
    let (tool, cmd_args) = parse_invocation(&args).expect("Valid invocation");
    assert_eq!(tool, "apt");
    assert_eq!(cmd_args, vec!["update"]);

    let symlink_args = vec![
        "/usr/local/bin/tail".to_string(),
        "-f".to_string(),
        "log".to_string(),
    ];
    let (tool2, cmd_args2) = parse_invocation(&symlink_args).expect("Valid invocation");
    assert_eq!(tool2, "tail");
    assert_eq!(cmd_args2, vec!["-f", "log"]);
}

#[test]
fn test_env_filter_logic() {
    let wl = ["ALLOWED".to_string()];
    let pairs = vec![
        ("ALLOWED".to_string(), "yes".to_string()),
        ("EVIL".to_string(), "no".to_string()),
    ];

    let filtered: Vec<_> = pairs.into_iter().filter(|(k, _)| wl.contains(k)).collect();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].0, "ALLOWED");
}
