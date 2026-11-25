#!/bin/sh
# Runs the release check on the Keeper binary inside a package, so the check
# covers the file a user installs and not only the bare binary it was built
# from.
#
#   usage: scripts/check-release-package.sh PACKAGE
#
# PACKAGE is a macOS .pkg (expanded with pkgutil, so macOS only), a Linux .deb
# (dpkg-deb, or ar and tar where dpkg-deb is missing), or a GoReleaser
# .tar.gz. The Windows Inno Setup installer has no portable extractor;
# release-build.yml installs it silently on Windows and checks the installed
# binary instead.
#
# Fails when the package holds no Keeper binary, and when any Keeper binary in
# it fails scripts/check-release-binary.sh.
set -eu

pkg="${1:?usage: $0 PACKAGE}"
here="$(cd "$(dirname "$0")" && pwd)"

if [ ! -f "$pkg" ]; then
  echo "$pkg: no such file" >&2
  exit 1
fi

pkg="$(cd "$(dirname "$pkg")" && pwd)/$(basename "$pkg")"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

case "$pkg" in
  *.pkg)
    pkgutil --expand-full "$pkg" "$tmp/x"
    ;;
  *.deb)
    mkdir -p "$tmp/x"
    if command -v dpkg-deb >/dev/null 2>&1; then
      dpkg-deb -x "$pkg" "$tmp/x"
    else
      (cd "$tmp" && ar x "$pkg")
      data="$(find "$tmp" -maxdepth 1 -name 'data.tar*' | head -n 1)"
      [ -n "$data" ] || { echo "$pkg: no data archive" >&2; exit 1; }
      tar -xf "$data" -C "$tmp/x"
    fi
    ;;
  *.tar.gz)
    mkdir -p "$tmp/x"
    tar -xzf "$pkg" -C "$tmp/x"
    ;;
  *)
    echo "$pkg: unsupported package type" >&2
    exit 2
    ;;
esac

find "$tmp/x" -type f \( -name dragpass-keeper -o -name dragpass-keeper.exe \) >"$tmp/bins"
if [ ! -s "$tmp/bins" ]; then
  echo "$pkg holds no Keeper binary" >&2
  exit 1
fi
while IFS= read -r bin; do
  "$here/check-release-binary.sh" "$bin" >/dev/null
  echo "$pkg: ${bin#"$tmp/x/"} passes the release check"
done <"$tmp/bins"
