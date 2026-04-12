#!/usr/bin/env bash

set -euo pipefail

cd /workspace

echo "============================================================"
echo "  secure-sudoers privileged test + coverage run"
echo "  Running as: $(id)"
echo "  Kernel: $(uname -r)"
echo "============================================================"

kernel_release="$(uname -r)"
kernel_major="${kernel_release%%.*}"
kernel_rest="${kernel_release#*.}"
kernel_minor="${kernel_rest%%.*}"

if ! [[ "$kernel_major" =~ ^[0-9]+$ && "$kernel_minor" =~ ^[0-9]+$ ]]; then
  echo "ERROR: Unable to parse kernel version from: $kernel_release" >&2
  exit 1
fi

if (( kernel_major < 4 || (kernel_major == 4 && kernel_minor < 19) )); then
  echo "ERROR: secure-sudoers requires Linux kernel 4.19+ (found: $kernel_release)" >&2
  exit 1
fi

echo "Kernel requirement satisfied (>= 4.19): $kernel_release"

if ! command -v bwrap >/dev/null 2>&1; then
  echo "ERROR: bubblewrap (bwrap) is required for privileged test runs" >&2
  exit 1
fi

echo "Running bubblewrap namespace smoke test..."
if bwrap --ro-bind / / /bin/sh -c 'uname -r' >/dev/null; then
  echo "Bubblewrap smoke test passed"
else
  echo "ERROR: bubblewrap smoke test failed" >&2
  exit 1
fi

echo "Building binaries for full-path E2E tests..."
cargo build --workspace --all-features --bins

echo "Running Bats full user journey tests..."
bats -t /workspace/tests/e2e_full_user_path.bats

export SECURE_SUDOERS_REQUIRE_ROOT=1
cargo llvm-cov --workspace --all-features --no-report -- --test-threads=1
cargo llvm-cov report --cobertura --output-path cobertura.xml
cargo llvm-cov report --summary-only
