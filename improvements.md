# secure-sudoers Deep Scan — Improvement Backlog

This file captures the full audit findings from a read-only functional and structural review.

Baseline status at audit time:
- `cargo test --workspace --all-features` passed.
- `cargo build --workspace --all-features` passed.

## 1) Functional Audit Findings

## 2) Niggles & Structural Improvement Areas

### 13. God-module tendencies in core security paths
1. **Location:** `crates/secure-sudoers/src/helpers.rs`, `crates/secure-sudoers/src/isolation.rs`, `crates/secure-sudoers-utils/src/modules/installer.rs`
2. **Issue:** Multiple responsibilities packed into single large modules.
3. **Impact:** Harder auditing, review overhead, and increased regression probability.
4. **Suggested Direction:** Split by concern (invocation parsing, policy loading, redaction, mount ops, installer IO).
