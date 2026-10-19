#!/bin/sh
# Starts a release binary and checks that it reports the expected version, that
# the MLS library answered across the C ABI (mls_linked.go reports "MLS library
# linked: ..."; the library-free build reports nothing), and that it refuses to
# run in E2E mode.
#
#   usage: scripts/release-probe.sh BINARY VERSION
#
# `dragpass-keeper version` touches neither the OS keychain nor the clipboard,
# so the probe runs on a bare CI machine or container and touches no user
# state. A release binary has no in-memory keyring: only a build with the
# keeper_e2e tag honours KEEPER_E2E_MODE, and a release build must exit on it.
set -eu

bin="${1:?usage: $0 BINARY VERSION}"
want="${2:?usage: $0 BINARY VERSION}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

if KEEPER_E2E_MODE=1 "$bin" version >"$tmp/e2e-out" 2>"$tmp/e2e-err"; then
  echo "probe: $bin ran with KEEPER_E2E_MODE=1; a release build must refuse it" >&2
  exit 1
fi
if ! grep -q 'release build without E2E support' "$tmp/e2e-err"; then
  echo "probe: $bin failed under KEEPER_E2E_MODE=1 without the release refusal" >&2
  cat "$tmp/e2e-err" >&2
  exit 1
fi

"$bin" version >"$tmp/body" 2>"$tmp/err" || true
if ! grep -qx "version: $want" "$tmp/body"; then
  echo "probe: $bin did not report version $want" >&2
  cat "$tmp/body" "$tmp/err" >&2
  exit 1
fi
if ! grep -q 'MLS library linked: ' "$tmp/body"; then
  echo "probe: $bin reported its version but not the MLS library" >&2
  cat "$tmp/body" "$tmp/err" >&2
  exit 1
fi
echo "probe: $bin version $want, $(grep -o 'MLS library linked: .*' "$tmp/body"), refuses E2E mode"
