# secure-sudoers Deep Scan — Improvement Backlog

This file captures the full audit findings from a read-only functional and structural review.

Baseline status at audit time:
- `cargo test --workspace --all-features` passed.
- `cargo build --workspace --all-features` passed.

## 1) Functional Audit Findings

* SUDO_COMMAND Parsing: While you handle basic spoofing, shlex::split on SUDO_COMMAND is a heuristic. In extremely high-security environments, some might
  prefer reading from /proc/self/cmdline directly.

## 2) Niggles & Structural Improvement Areas

### 13. God-module tendencies in core security paths
1. **Location:** `crates/secure-sudoers/src/helpers.rs`, `crates/secure-sudoers/src/isolation.rs`, `crates/secure-sudoers-utils/src/modules/installer.rs`
2. **Issue:** Multiple responsibilities packed into single large modules.
3. **Impact:** Harder auditing, review overhead, and increased regression probability.
4. **Suggested Direction:** Split by concern (invocation parsing, policy loading, redaction, mount ops, installer IO).

### 15. Dependency surface can be tightened in `secure-sudoers`
1. **Location:** `crates/secure-sudoers/Cargo.toml`
2. **Issue:** Some dependencies appear heavier than runtime requirements (e.g., keygen/testing-oriented crates in runtime crate).
3. **Impact:** Larger attack surface and maintenance overhead.
4. **Suggested Direction:** Re-audit runtime vs dev usage and move non-runtime crates to `dev-dependencies` where possible.

### 16. Critical network update path lacks dedicated automated tests
1. **Location:** `crates/secure-sudoers-utils/src/modules/network.rs` and test suite coverage
2. **Issue:** No focused unit/integration tests for update success/failure matrix (downgrade, oversize body, bad sig, atomic replacement behavior).
3. **Impact:** Elevated regression risk in a security-sensitive update mechanism.
4. **Suggested Direction:** Add module-level tests with local HTTP fixtures and explicit rollback/assertion checks.
