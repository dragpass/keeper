#!/bin/sh
# Starts a release binary, sends it one native-messaging ping, and checks that
# it answers with the expected version and that the MLS library answered
# across the C ABI at startup (mls_linked.go logs "MLS library linked: ...";
# the library-free build logs nothing).
#
#   usage: scripts/release-probe.sh BINARY VERSION
#
# KEEPER_E2E_MODE=1 swaps the OS keychain and clipboard for in-memory ones, so
# the probe runs on a bare CI machine or container and touches no user state.
set -eu

bin="${1:?usage: $0 BINARY VERSION}"
want="${2:?usage: $0 BINARY VERSION}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

req='{"action":"ping"}'
# Native messaging frames each message with a 4-byte little-endian length.
printf "\\$(printf '%03o' "${#req}")\\000\\000\\000%s" "$req" \
  | KEEPER_E2E_MODE=1 "$bin" >"$tmp/out" 2>"$tmp/err" || true

if ! grep -aq "\"version\":\"$want\"" "$tmp/out"; then
  echo "probe: $bin did not answer ping with version $want" >&2
  cat "$tmp/err" >&2
  exit 1
fi
if ! grep -q 'MLS library linked: ' "$tmp/err"; then
  echo "probe: $bin answered ping but did not report the MLS library" >&2
  cat "$tmp/err" >&2
  exit 1
fi
echo "probe: $bin version $want, $(grep -o 'MLS library linked: .*' "$tmp/err")"
