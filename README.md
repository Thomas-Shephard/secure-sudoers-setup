# Secure Sudoers

Secure Sudoers is a policy-driven sudo delegation framework that provides granular, argument-level control over privileged command execution.

The tool is intended to replace traditional access to sudo by enforcing the **principle of least privilege** by validating every parameter before execution.

## Core Features
- **Argument-Level Control**: Validate flags, positional arguments, and file paths using regex or fixed choices.
- **Cryptographic Security**: Policies are signed with Ed25519; unauthorized or modified policies are rejected.
- **Process Isolation**: Secure sandboxing with network, PID, and mount namespaces (optional per tool).
- **Tamper Resistance**: Automatically applies the immutable bit (equivalent to `chattr +i`) to configuration and binaries.
- **Auto Sudo Configuration**: Generates a single `sudoers.d` drop-in to manage all delegated tools.
- **Security Telemetry**: Every command attempt emits a structured JSON security event to `LOG_AUTHPRIV`, providing immutable audit trails.

## How It Works
1. **Invocation**: Run a managed tool entry point (e.g., `/usr/local/bin/apt`) that hard-links to the `secure-sudoers` binary.
2. **Identification**: The binary identifies the tool name from the calling context.
3. **Verification**: The system loads the signed JSON policy and verifies it against the trusted public key.
4. **Validation**: Arguments are matched against the rules in the policy.
5. **Execution**: If valid, the process executes the command in a secure, isolated environment.

## System Requirements
- **Linux kernel**: **4.19 or newer** (enforced at runtime by `secure-sudoers` and `secure-sudoers-utils`).
- **Privileges**: Root is required for `install`, `unlock`, and `update`.

Optional namespace smoke test with bubblewrap:
```bash
bwrap --ro-bind / / /bin/sh -c 'uname -r'
```

## Setup Guide

Follow these steps to set up Secure Sudoers on your system.

### 1. Install
Download the `secure-sudoers` and `secure-sudoers-utils` binaries from [GitHub Releases](https://github.com/thomas-shephard/secure-sudoers/releases).

### 2. Generate Keys
Use the built-in utility command to generate a new Ed25519 keypair:
```bash
sudo secure-sudoers-utils gen-keys
```
This generates:
- `secure_sudoers_private_key.pem` (keep this secret)
- `secure_sudoers_public_key.pem`

Move the public key to the trusted system directory:
```bash
sudo mkdir -p /etc/secure-sudoers
sudo mv secure_sudoers_public_key.pem /etc/secure-sudoers/
```

### 3. Create, Validate, and Sign Policy
Define tools and their restrictions in `/etc/secure-sudoers/policy.json`. See [POLICY.md](POLICY.md) for the full specification.

Before signing, it is recommended to validate the policy for errors:
```bash
secure-sudoers-utils check /etc/secure-sudoers/policy.json
```

Once the policy is ready, sign it using the private key:
```bash
sudo secure-sudoers-utils sign /etc/secure-sudoers/policy.json ./secure_sudoers_private_key.pem
```
This creates `/etc/secure-sudoers/policy.json.sig`.
The signature file is stored as raw 64-byte Ed25519 signature bytes.

### 4. Install the Environment
Deploy the configuration and set up tool entry points:
```bash
sudo secure-sudoers-utils install
```
This command performs the following actions:
- Verifies `policy.json.sig` against `/etc/secure-sudoers/secure_sudoers_public_key.pem` before applying any changes.
- Creates hard-link tool entry points in `/usr/local/bin` for every tool defined in your policy.
- Writes a secure sudoers drop-in to `/etc/sudoers.d/secure-sudoers`.
- Protects the binaries, policy JSON, policy signature, trusted public key, sudoers drop-in, and hard-link tool entry points with the immutable bit (equivalent to `chattr +i`).
- Returns an error if immutable hardening cannot be applied to all managed files.
- May leave partial changes when an installation error occurs; run `unlock`, correct the issue, and re-run `install`.

## Administration Utility

The `secure-sudoers-utils` tool provides several subcommands to manage the system:

| Command                         | Description                                                                                                         |
|---------------------------------|---------------------------------------------------------------------------------------------------------------------|
| `gen-keys`                      | Generates a new Ed25519 keypair.                                                                                    |
| `sign <policy_path> <key_path>` | Signs a policy JSON file with a private key.                                                                        |
| `check <policy_path>`           | Validates a policy JSON file for correctness and best practices.                                                    |
| `install`                       | Sets up hard-link tool entry points and sudoers configuration (requires `policy.json`, `policy.json.sig`, and `/etc/secure-sudoers/secure_sudoers_public_key.pem`). |
| `unlock`                        | Removes the immutable bit from all managed files to allow for updates.                                              |
| `update <url> <pubkey_path>`    | Securely fetches and verifies policy updates over HTTPS.                                                            |

### Updating Policies
To update your configuration, you must first unlock the files:
```bash
sudo secure-sudoers-utils unlock
# ... modify policy and re-sign ...
sudo secure-sudoers-utils install
```

## Advanced Features

### Network Updates
Secure Sudoers can securely fetch and verify policy updates over HTTPS:
```bash
sudo secure-sudoers-utils update https://your-server.com/policy.json /etc/secure-sudoers/secure_sudoers_public_key.pem
```
The utility ensures the policy `serial` is higher than the current version to prevent downgrade attacks.

## Security Telemetry

Every command validation and execution attempt emits a structured JSON security event to the system logger (`LOG_AUTHPRIV`, facility `auth`).

### Event Schema

Each log entry is a JSON object with the following mandatory fields:

```json
{
  "event_id":  "SEC-101",
  "txn_id":    "a3f7c291",
  "timestamp": "2026-03-10T21:28:35Z",
  "identity": {
    "user":      "alice",
    "uid":       1000,
    "euid":      0,
    "sudo_uid":  1000,
    "account_type": "local"
  },
  "context": {
    "tool":         "apt",
    "binary_path":  "/usr/bin/apt",
    "binary_hash":  "e3b0c44298fc1c149afb..."
  },
  "policy": {
    "status":   "allowed",
    "rule_id":  "apt",
    "reason":   null
  },
  "args": ["install", "vim"]
}
```

### Event ID Codes

| Code      | Meaning                                                          |
|-----------|------------------------------------------------------------------|
| `SEC-101` | Command approved and forwarded for execution.                    |
| `SEC-403` | Policy violation — command denied by policy.                     |
| `SEC-500` | Identity spoofing detected or invocation parse failure.          |
| `SEC-503` | Supervisor / execution failure after policy approval.            |

### Transaction Correlation

A unique `txn_id` (8-char hex) is generated at the start of each execution. All log entries from a single invocation share the same `txn_id`.

```bash
# Correlate all events for a single denied invocation:
journalctl -t secure-sudoers | grep '"txn_id":"a3f7c291"'
```

### Identity Integrity

The `identity` block always captures the **real** `uid` and `euid` via `getuid()`/`geteuid()` syscalls, making it immune to `SUDO_USER` spoofing attempts.

It also includes `account_type`, classified as:
- `system`: username is present in local `/etc/passwd` and `uid < 1000`
- `local`: username is present in local `/etc/passwd` and `uid >= 1000`
- `network`: username resolves via NSS but is not present in local `/etc/passwd` (e.g., LDAP/AD/SSSD)
- `unknown`: fallback when identity resolution or `/etc/passwd` read/scan fails

### Binary Hash Verification

Before execution, the SHA-256 hash of the resolved binary is computed directly from the secure file descriptor obtained during path resolution.

### Log Format

When `log_destination` is `syslog` (default), events are written as **raw JSON** to `LOG_AUTHPRIV`. When `log_destination` is `stdout`, events are printed in human-readable tracing format (or JSON if `log_format: "json"` is set).

## Building from Source

```bash
# Standard build
cargo build --release

# Build utils with network update support
cargo build -p secure-sudoers-utils --release --features network-update
```
