#!/bin/sh
# Fails when a Linux binary needs a newer glibc than the baseline it is sold
# for, or links libX11 at load time. The clipboard opens libX11 with dlopen,
# so a NEEDED entry for it would mean a machine without X11 could no longer
# start Keeper at all.
#
#   usage: scripts/check-glibc-baseline.sh BINARY [MAX_GLIBC]   (default 2.31)
set -eu

bin="${1:?usage: $0 BINARY [MAX_GLIBC]}"
max="${2:-2.31}"

highest="$(objdump -T "$bin" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/^GLIBC_//' | sort -uV | tail -n 1)"
if [ -z "$highest" ]; then
  echo "glibc: $bin has no GLIBC_ symbol versions (is it a cgo build?)" >&2
  exit 1
fi
top="$(printf '%s\n%s\n' "$highest" "$max" | sort -V | tail -n 1)"
if [ "$top" != "$max" ]; then
  echo "glibc: $bin needs GLIBC_$highest, newer than the GLIBC_$max baseline" >&2
  objdump -T "$bin" | grep "GLIBC_$highest" >&2
  exit 1
fi

needed="$(readelf -d "$bin" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p')"
if printf '%s\n' "$needed" | grep -q '^libX11'; then
  echo "glibc: $bin links libX11 at load time; it must stay a runtime dlopen" >&2
  exit 1
fi
echo "glibc: $bin needs at most GLIBC_$highest (baseline GLIBC_$max); NEEDED: $(printf '%s' "$needed" | tr '\n' ' ')"
