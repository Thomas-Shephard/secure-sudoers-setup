#!/usr/bin/env bats

setup() {
  export TEST_ROOT="/tmp/ss-e2e"
  export KEYS_DIR="${TEST_ROOT}/keys"
  export PUBLIC_KEY_PATH="/etc/secure-sudoers/secure_sudoers_public_key.pem"
  export POLICY_PATH="/etc/secure-sudoers/policy.json"
  export PRIVATE_KEY_PATH="${KEYS_DIR}/secure_sudoers_private_key.pem"
  export PUBLIC_KEY_LOCAL_PATH="${KEYS_DIR}/secure_sudoers_public_key.pem"

  mkdir -p "$TEST_ROOT" "$KEYS_DIR" /etc/secure-sudoers /etc/sudoers.d /usr/local/bin
  cp -f /workspace/target/debug/secure-sudoers /usr/local/bin/secure-sudoers
  cp -f /workspace/target/debug/secure-sudoers-utils /usr/local/bin/secure-sudoers-utils
  chmod 0755 /usr/local/bin/secure-sudoers /usr/local/bin/secure-sudoers-utils
  rm -f "$PRIVATE_KEY_PATH" "$PUBLIC_KEY_LOCAL_PATH"
  rm -f "$PUBLIC_KEY_PATH" "$POLICY_PATH" "${POLICY_PATH}.sig"
  rm -f /usr/local/bin/echo /usr/local/bin/cat 2>/dev/null || true
}

teardown() {
  /workspace/target/debug/secure-sudoers-utils unlock >/dev/null 2>&1 || true
  mkdir -p /etc/secure-sudoers /etc/sudoers.d /usr/local/bin
  rm -f "$PUBLIC_KEY_PATH" "$POLICY_PATH" "${POLICY_PATH}.sig"
  rm -f /etc/sudoers.d/secure-sudoers
  rm -f /usr/local/bin/echo /usr/local/bin/cat 2>/dev/null || true
  rm -f /usr/local/bin/secure-sudoers /usr/local/bin/secure-sudoers-utils 2>/dev/null || true
  rm -rf "$TEST_ROOT"
}

prepare_keys() {
  (
    cd "$KEYS_DIR"
    /workspace/target/debug/secure-sudoers-utils gen-keys >/dev/null
  )
  cp "$PUBLIC_KEY_LOCAL_PATH" "$PUBLIC_KEY_PATH"
}

write_policy_v1() {
  cat >"$POLICY_PATH" <<'JSON'
{
  "version": "1.0",
  "serial": 1,
  "global_settings": {
    "log_destination": "stdout",
    "log_format": "text",
    "admin_contact": "Contact: test-admin@example.com",
    "blocked_paths": ["/etc/shadow"]
  },
  "tools": {
    "echo": {
      "id": "echo-v1",
      "real_binary": "/usr/bin/echo",
      "help_description": "echo test tool",
      "verbs": ["ok"],
      "parameters": {}
    },
    "cat": {
      "id": "cat-v1",
      "real_binary": "/usr/bin/cat",
      "help_description": "cat test tool",
      "parameters": {},
      "positional": {
        "type": "path",
        "regex": "^/etc/hosts$"
      }
    }
  }
}
JSON
}

write_policy_v2() {
  cat >"$POLICY_PATH" <<'JSON'
{
  "version": "1.0",
  "serial": 2,
  "global_settings": {
    "log_destination": "stdout",
    "log_format": "text",
    "admin_contact": "Contact: test-admin@example.com",
    "blocked_paths": []
  },
  "tools": {
    "echo": {
      "id": "echo-v2",
      "real_binary": "/usr/bin/echo",
      "help_description": "echo test tool",
      "verbs": ["ok"],
      "parameters": {}
    },
    "cat": {
      "id": "cat-v2",
      "real_binary": "/usr/bin/cat",
      "help_description": "cat test tool",
      "parameters": {},
      "positional": {
        "type": "path",
        "regex": "^/etc/.*"
      }
    }
  }
}
JSON
}

@test "gen-keys creates keypair files" {
  run bash -lc "cd '$KEYS_DIR' && /workspace/target/debug/secure-sudoers-utils gen-keys"
  [ "$status" -eq 0 ]
  [ -f "$PRIVATE_KEY_PATH" ]
  [ -f "$PUBLIC_KEY_LOCAL_PATH" ]
}

@test "check validates policy before signing" {
  prepare_keys
  write_policy_v1

  run /workspace/target/debug/secure-sudoers-utils check "$POLICY_PATH"
  [ "$status" -eq 0 ]
  [[ "$output" == *"is valid"* ]]
}

@test "sign creates detached signature for policy" {
  prepare_keys
  write_policy_v1

  run /workspace/target/debug/secure-sudoers-utils sign "$POLICY_PATH" "$PRIVATE_KEY_PATH"
  [ "$status" -eq 0 ]
  [ -f "${POLICY_PATH}.sig" ]
}

@test "install provisions hard-link entry points and sudoers drop-in" {
  prepare_keys
  write_policy_v1
  /workspace/target/debug/secure-sudoers-utils sign "$POLICY_PATH" "$PRIVATE_KEY_PATH" >/dev/null

  run /workspace/target/debug/secure-sudoers-utils install
  [ "$status" -eq 0 ]
  [ -f /usr/local/bin/echo ]
  [ -f /usr/local/bin/cat ]
  [ ! -L /usr/local/bin/echo ]
  [ ! -L /usr/local/bin/cat ]
  echo_identity="$(stat -c '%d:%i' /usr/local/bin/echo)"
  cat_identity="$(stat -c '%d:%i' /usr/local/bin/cat)"
  binary_identity="$(stat -c '%d:%i' /usr/local/bin/secure-sudoers)"
  [ "$echo_identity" = "$binary_identity" ]
  [ "$cat_identity" = "$binary_identity" ]
  [ -f /etc/sudoers.d/secure-sudoers ]
}

@test "allowed command succeeds under installed policy" {
  prepare_keys
  write_policy_v1
  /workspace/target/debug/secure-sudoers-utils sign "$POLICY_PATH" "$PRIVATE_KEY_PATH" >/dev/null
  /workspace/target/debug/secure-sudoers-utils install >/dev/null

  run /workspace/target/debug/secure-sudoers echo ok hello-world
  [ "$status" -eq 0 ]
  [[ "$output" == *"hello-world"* ]]
}

@test "blocked command is denied under policy v1" {
  prepare_keys
  write_policy_v1
  /workspace/target/debug/secure-sudoers-utils sign "$POLICY_PATH" "$PRIVATE_KEY_PATH" >/dev/null
  /workspace/target/debug/secure-sudoers-utils install >/dev/null

  run /workspace/target/debug/secure-sudoers cat /etc/shadow
  [ "$status" -ne 0 ]
  [[ "$output" == *"Access denied"* ]]
}

@test "unlock permits policy replacement and reinstall" {
  prepare_keys
  write_policy_v1
  /workspace/target/debug/secure-sudoers-utils sign "$POLICY_PATH" "$PRIVATE_KEY_PATH" >/dev/null
  /workspace/target/debug/secure-sudoers-utils install >/dev/null

  run /workspace/target/debug/secure-sudoers-utils unlock
  if [ "$status" -ne 0 ]; then
    [[ "$output" == *"Some files could not be unlocked"* ]]
  fi

  write_policy_v2
  run /workspace/target/debug/secure-sudoers-utils sign "$POLICY_PATH" "$PRIVATE_KEY_PATH"
  [ "$status" -eq 0 ]
  run /workspace/target/debug/secure-sudoers-utils install
  [ "$status" -eq 0 ]
}

@test "policy update changes denied command to allowed" {
  prepare_keys
  write_policy_v1
  /workspace/target/debug/secure-sudoers-utils sign "$POLICY_PATH" "$PRIVATE_KEY_PATH" >/dev/null
  /workspace/target/debug/secure-sudoers-utils install >/dev/null

  run /workspace/target/debug/secure-sudoers cat /etc/shadow
  [ "$status" -ne 0 ]

  run /workspace/target/debug/secure-sudoers-utils unlock
  if [ "$status" -ne 0 ]; then
    [[ "$output" == *"Some files could not be unlocked"* ]]
  fi
  write_policy_v2
  /workspace/target/debug/secure-sudoers-utils sign "$POLICY_PATH" "$PRIVATE_KEY_PATH" >/dev/null
  /workspace/target/debug/secure-sudoers-utils install >/dev/null

  run /workspace/target/debug/secure-sudoers cat /etc/shadow
  [ "$status" -eq 0 ]
}

@test "invalid signature causes policy load failure" {
  prepare_keys
  write_policy_v1
  /workspace/target/debug/secure-sudoers-utils sign "$POLICY_PATH" "$PRIVATE_KEY_PATH" >/dev/null
  /workspace/target/debug/secure-sudoers-utils install >/dev/null

  run /workspace/target/debug/secure-sudoers-utils unlock
  if [ "$status" -ne 0 ]; then
    [[ "$output" == *"Some files could not be unlocked"* ]]
  fi
  run bash -lc "printf 'corrupt-signature' > '${POLICY_PATH}.sig'"
  [ "$status" -eq 0 ]
  run /workspace/target/debug/secure-sudoers echo ok should-fail
  [ "$status" -ne 0 ]
  [[ "$output" == *"Cannot load policy"* ]]
}

@test "symlink invocation works for allowed tool" {
  prepare_keys
  write_policy_v1
  /workspace/target/debug/secure-sudoers-utils sign "$POLICY_PATH" "$PRIVATE_KEY_PATH" >/dev/null
  /workspace/target/debug/secure-sudoers-utils install >/dev/null

  run /usr/local/bin/echo ok via-symlink
  [ "$status" -eq 0 ]
  [[ "$output" == *"via-symlink"* ]]
}

@test "unknown tool is denied and contact is shown" {
  prepare_keys
  write_policy_v1
  /workspace/target/debug/secure-sudoers-utils sign "$POLICY_PATH" "$PRIVATE_KEY_PATH" >/dev/null
  /workspace/target/debug/secure-sudoers-utils install >/dev/null

  run /workspace/target/debug/secure-sudoers unknown-tool arg1
  [ "$status" -ne 0 ]
  [[ "$output" == *"Access denied"* ]]
  [[ "$output" == *"Contact: test-admin@example.com"* ]]
}

@test "invalid verb is denied for configured tool" {
  prepare_keys
  write_policy_v1
  /workspace/target/debug/secure-sudoers-utils sign "$POLICY_PATH" "$PRIVATE_KEY_PATH" >/dev/null
  /workspace/target/debug/secure-sudoers-utils install >/dev/null

  run /workspace/target/debug/secure-sudoers echo badverb hello
  [ "$status" -ne 0 ]
  [[ "$output" == *"Access denied"* ]]
  [[ "$output" == *"Verb"* ]]
}

@test "policy regex restriction denies non-matching but safe path" {
  prepare_keys
  write_policy_v1
  /workspace/target/debug/secure-sudoers-utils sign "$POLICY_PATH" "$PRIVATE_KEY_PATH" >/dev/null
  /workspace/target/debug/secure-sudoers-utils install >/dev/null

  run /workspace/target/debug/secure-sudoers cat /etc/passwd
  [ "$status" -ne 0 ]
  [[ "$output" == *"Access denied"* ]]
}

@test "tampering with signed policy is rejected at runtime" {
  prepare_keys
  write_policy_v1
  /workspace/target/debug/secure-sudoers-utils sign "$POLICY_PATH" "$PRIVATE_KEY_PATH" >/dev/null
  /workspace/target/debug/secure-sudoers-utils install >/dev/null

  /workspace/target/debug/secure-sudoers-utils unlock >/dev/null 2>&1 || true
  printf "\n" >> "$POLICY_PATH"

  run /workspace/target/debug/secure-sudoers echo ok should-fail
  [ "$status" -ne 0 ]
  [[ "$output" == *"Cannot load policy"* ]]
}

@test "missing signature file is rejected at runtime" {
  prepare_keys
  write_policy_v1
  /workspace/target/debug/secure-sudoers-utils sign "$POLICY_PATH" "$PRIVATE_KEY_PATH" >/dev/null
  /workspace/target/debug/secure-sudoers-utils install >/dev/null

  /workspace/target/debug/secure-sudoers-utils unlock >/dev/null 2>&1 || true
  rm -f "${POLICY_PATH}.sig"

  run /workspace/target/debug/secure-sudoers echo ok should-fail
  [ "$status" -ne 0 ]
  [[ "$output" == *"Cannot load policy"* ]]
}

@test "SUDO_COMMAND mismatch is detected as spoofing" {
  prepare_keys
  write_policy_v1
  /workspace/target/debug/secure-sudoers-utils sign "$POLICY_PATH" "$PRIVATE_KEY_PATH" >/dev/null
  /workspace/target/debug/secure-sudoers-utils install >/dev/null

  run env SUDO_COMMAND="/usr/bin/cat /etc/hosts" /workspace/target/debug/secure-sudoers echo ok hi
  [ "$status" -ne 0 ]
  [[ "$output" == *"Spoofing attempt detected"* ]]
}

@test "update command rejects non-https URL" {
  prepare_keys
  run /workspace/target/debug/secure-sudoers-utils update "http://example.invalid/policy.json" "$PUBLIC_KEY_PATH"
  [ "$status" -ne 0 ]
  [[ "$output" == *"URL must use HTTPS"* ]]
}
