#!/bin/sh
# Lists the Keeper's items in the macOS login Keychain, and with "delete"
# removes them. Used by `make refresh`.
#
#   usage: scripts/keychain-slots.sh list|delete
#
# Environment (set by the Makefile):
#   KEEPER_KEYCHAIN_SERVICE          the service every Keeper item is stored under
#   KEEPER_KEYCHAIN_ACCOUNTS         exact account names of the current slots
#   KEEPER_KEYCHAIN_ACCOUNT_PREFIXES prefixes of slots whose names carry an id
#   SECURITY                         the security(1) binary (default: security)
#
# Only items whose account is a current slot are deleted. Anything else under
# the service (a slot an older Keeper wrote and this one no longer knows) is
# listed and left alone.
#
# Items are found with `security dump-keychain`, which prints attributes only:
# without -d it never reads a secret, so listing prompts for nothing.
set -eu

mode="${1:?usage: $0 list|delete}"
case "$mode" in
list | delete) ;;
*)
	echo "usage: $0 list|delete" >&2
	exit 2
	;;
esac

service="${KEEPER_KEYCHAIN_SERVICE:?}"
accounts="${KEEPER_KEYCHAIN_ACCOUNTS:?}"
prefixes="${KEEPER_KEYCHAIN_ACCOUNT_PREFIXES:?}"
security="${SECURITY:-security}"

is_current_slot() {
	for a in $accounts; do
		[ "$1" = "$a" ] && return 0
	done
	for p in $prefixes; do
		case "$1" in "$p"*) return 0 ;; esac
	done
	return 1
}

found="$("$security" dump-keychain | awk -v svc="$service" '
	function value(line) {
		sub(/^[^=]*="/, "", line)
		sub(/"$/, "", line)
		return line
	}
	function flush() {
		if (class == "genp" && svce == svc && acct != "") print acct
		class = ""; svce = ""; acct = ""
	}
	/^keychain: / { flush() }
	/^class: / { class = $2; gsub(/"/, "", class) }
	/^[[:space:]]*"acct"<blob>="/ { acct = value($0) }
	/^[[:space:]]*"svce"<blob>="/ { svce = value($0) }
	END { flush() }
' | sort -u)"

current=""
other=""
for acct in $found; do
	if is_current_slot "$acct"; then
		current="$current $acct"
	else
		other="$other $acct"
	fi
done

if [ "$mode" = list ]; then
	echo "Keychain items under service $service:"
	if [ -z "$current" ]; then
		echo "  (no current Keeper slot found)"
	fi
	for acct in $current; do
		echo "  will delete: $acct"
	done
	for acct in $other; do
		echo "  left alone (not a current slot): $acct"
	done
	exit 0
fi

for acct in $current; do
	if "$security" delete-generic-password -s "$service" -a "$acct" >/dev/null 2>&1; then
		echo "  deleted: $acct"
	else
		echo "  could not delete: $acct"
	fi
done
