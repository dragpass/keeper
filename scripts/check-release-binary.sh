#!/bin/sh
# The release check for one Keeper binary. Every distribution path runs it on
# the binary it ships: the Makefile package targets, release-build.yml, the
# GoReleaser post-build hook, and the package checks in
# scripts/check-release-package.sh.
#
#   usage: scripts/check-release-binary.sh BINARY
#
# Fails when BINARY
#   - was built without the mls tag,
#   - was built with a test-only tag (keeper_e2e, or the keeper_killseam crash
#     seams),
#   - does not carry the root public key ROOT_PUBLIC_KEY_PEM_BASE64 names
#     (checked by scripts/check-root-public-key.sh first, so a missing or
#     malformed value fails before the binary is read), or
#   - carries E2E-only code.
#
# Build tags are read from the build info; the root key and the strings are
# read from the binary itself, since -trimpath leaves -ldflags out of the build
# info. The strings survive a stripped binary (-s -w), unlike symbols. Besides
# the E2E mode they cover the dev App origin opt-in and the root key override;
# a release build refuses those variables by prefix (e2e_release.go), so their
# full names never reach it.
set -eu

bin="${1:?usage: $0 BINARY}"
here="$(cd "$(dirname "$0")" && pwd)"

"$here/check-root-public-key.sh" >/dev/null

if [ ! -f "$bin" ]; then
  echo "$bin: no such file" >&2
  exit 1
fi

info="$(go version -m "$bin")" || {
  echo "$bin: no Go build info" >&2
  exit 1
}
tags="$(printf '%s\n' "$info" | sed -n 's/^[[:space:]]*build[[:space:]]*-tags=//p')"
case ",$tags," in
  *,mls,*) ;;
  *)
    echo "$bin was built without the mls tag (tags: ${tags:-none})" >&2
    exit 1
    ;;
esac
for tag in keeper_e2e keeper_killseam; do
  if printf '%s\n' "$info" | grep -q "$tag"; then
    echo "$bin was built with the $tag tag" >&2
    exit 1
  fi
done

if ! LC_ALL=C grep -aqF "$ROOT_PUBLIC_KEY_PEM_BASE64" "$bin"; then
  echo "$bin does not carry the root public key" >&2
  exit 1
fi

for s in KEEPER_E2E_KEYRING_FILE KEEPER_E2E_OS_CLIPBOARD clipboard_get_last_hash \
  DRAGPASS_KEEPER_DEV_APP_ORIGIN KEEPER_ROOT_PUBLIC_KEY_BASE64 \
  KEEPER_E2E_LOCAL_TARGET_PORTS KEEPER_E2E_LOCAL_TARGET_CA_FILE; do
  if LC_ALL=C grep -aq "$s" "$bin"; then
    echo "$bin carries E2E-only code ($s)" >&2
    exit 1
  fi
done

echo "$bin: mls tag, no test-only tag, no E2E-only code, root public key built in"
