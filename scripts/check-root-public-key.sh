#!/bin/sh
# Checks the root public key every release build embeds.
#
#   usage: scripts/check-root-public-key.sh
#
# ROOT_PUBLIC_KEY_PEM_BASE64 is the Base64 of the root public key PEM. Every
# distribution path reads this one name: the Makefile build and package
# targets, release-build.yml (macOS, Linux, Windows), the GoReleaser Homebrew
# build, and through the published installer the WinGet submission. In GitHub
# Actions it comes from the repository variable of the same name.
#
# There is no default and no fallback key. A missing or malformed value fails
# here, so a release build stops before it produces a binary that would refuse
# every refresh_server_keys request (anchor.UnverifiedServerKeysAllowed is
# false in a release build). A value that holds private key material fails
# too: the root private key never belongs in a build input.
set -eu

key="${ROOT_PUBLIC_KEY_PEM_BASE64:-}"
if [ -z "$key" ]; then
  echo "ROOT_PUBLIC_KEY_PEM_BASE64 is not set; a release build must embed the production root public key" >&2
  exit 1
fi

# Base64 alphabet only, so the value cannot break the -ldflags -X argument or
# the shell and make lines that carry it.
case "$key" in
  *[!A-Za-z0-9+/=]*)
    echo "ROOT_PUBLIC_KEY_PEM_BASE64 is not a single-line Base64 value" >&2
    exit 1
    ;;
esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

if ! printf '%s' "$key" | base64 -d >"$tmp/root.pem" 2>/dev/null; then
  echo "ROOT_PUBLIC_KEY_PEM_BASE64 does not decode as Base64" >&2
  exit 1
fi

if grep -q 'PRIVATE KEY' "$tmp/root.pem"; then
  echo "ROOT_PUBLIC_KEY_PEM_BASE64 holds private key material; set the public key only" >&2
  exit 1
fi

# The forms anchor.VerifyServerKeyRootSignature parses
# (jwt.ParseRSAPublicKeyFromPEM).
if ! grep -Eq '^-----BEGIN (RSA )?PUBLIC KEY-----$' "$tmp/root.pem" ||
  ! grep -Eq '^-----END (RSA )?PUBLIC KEY-----$' "$tmp/root.pem"; then
  echo "ROOT_PUBLIC_KEY_PEM_BASE64 does not decode to a PEM public key" >&2
  exit 1
fi

# The same fingerprint Keeper stores and the server reports:
# "sha256:" + hex(sha256(PEM bytes)). It is public and identifies the key in
# build logs.
if command -v sha256sum >/dev/null 2>&1; then
  digest="$(sha256sum "$tmp/root.pem" | awk '{print $1}')"
else
  digest="$(shasum -a 256 "$tmp/root.pem" | awk '{print $1}')"
fi
echo "root public key fingerprint: sha256:$digest"
