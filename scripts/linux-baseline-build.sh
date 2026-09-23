#!/bin/sh
# Builds a Linux release binary on the glibc baseline the package promises.
#
# Runs as root inside an ubuntu:20.04 container (glibc 2.31) of the same
# architecture as the binary, with the repository mounted at the working
# directory and a Linux Go toolchain mounted at /usr/local/go. A cgo binary
# needs the glibc symbol versions of the machine it was linked on, so building
# on the oldest supported distribution is what lets it run there and on
# anything newer.
#
#   usage: scripts/linux-baseline-build.sh amd64|arm64 [VERSION]
#
# HOST_UID / HOST_GID, when set, hand the outputs back to the invoking user so
# the host steps that follow can clean up after a root-owned container.
set -eu

arch="${1:?usage: $0 amd64|arm64 [VERSION]}"
version="${2:-1.0}"
case "$arch" in
  amd64) machine=x86_64; bin=dragpass-keeper-linux-x86_64 ;;
  arm64) machine=aarch64; bin=dragpass-keeper-linux-arm64 ;;
  *) echo "unsupported arch: $arch" >&2; exit 2 ;;
esac
if [ "$(uname -m)" != "$machine" ]; then
  echo "container is $(uname -m), expected $machine: build natively, not across arches" >&2
  exit 2
fi

# libx11-dev is for headers only. clipboard_linux.c includes <X11/Xlib.h> to
# declare the function pointers it fills from dlopen("libX11.so"), and links
# nothing but -ldl. curl and ca-certificates fetch rustup, make runs the
# Makefile recipe.
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  gcc libc6-dev libx11-dev make curl ca-certificates >/dev/null

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
  | sh -s -- -y -q --profile minimal --default-toolchain "${RUST_TOOLCHAIN:-stable}"
export PATH="/usr/local/go/bin:$HOME/.cargo/bin:$PATH"
export GOCACHE=/tmp/go-cache
# The container has no git, and the worktree's .git may point at a host path.
export GOFLAGS=-buildvcs=false

ldd --version | head -n 1
rustc --version
go version

rm -f "$bin"
make "build-linux-$arch" VERSION="$version"

if [ -n "${HOST_UID:-}" ]; then
  chown -R "$HOST_UID:${HOST_GID:-$HOST_UID}" "$bin" mls/target
fi
