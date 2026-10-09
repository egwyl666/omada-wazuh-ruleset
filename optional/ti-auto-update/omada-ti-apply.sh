#!/usr/bin/env bash
# omada-ti-apply.sh - OPTIONAL automatic update, part 2 of 2 (root, no network).
#
# Started by omada-ti-apply.path when omada-ti-fetch.sh has created $STATE_DIR/ready.
# For every list in $STATE_DIR/pending:
#   1. copies it into a root-only temp dir and validates the format strictly
#      (the files come from an unprivileged user, so nothing is trusted);
#   2. skips it if it equals the installed list;
#   3. otherwise backs up the installed list and installs the new one (owner wazuh:wazuh, 660).
# If anything changed: checks the Wazuh configuration; if the check fails, restores the backups.
# It NEVER restarts wazuh-manager: Wazuh compiles CDB lists only at start, so the new lists
# take effect at the next planned restart of the manager (done by an admin).
#
# Only these list names are accepted; any other file in pending/ is ignored.

set -uo pipefail

STATE_DIR=${STATE_DIR:-/var/lib/omada-ti}
LISTS=${LISTS:-/var/ossec/etc/lists}
BACKUP_DIR=${BACKUP_DIR:-/var/backups/omada-ti}
OWNER=${OWNER:-wazuh:wazuh}                 # Wazuh < 4.3: ossec:ossec
ANALYSISD=${ANALYSISD:-/var/ossec/bin/wazuh-analysisd}
MAX_BYTES=${MAX_BYTES:-20000000}
ALLOWED="ti-feodo-c2 ti-tor-relays ti-mining-pools telegram-ips"

IP='([0-9]{1,3}\.){3}[0-9]{1,3}'
PLACEHOLDER_RE='^0\.0\.0\.0:placeholder-replace-me$'

log() { echo "$*"; }

[ -e "$STATE_DIR/ready" ] || { log "no $STATE_DIR/ready, nothing to do"; exit 0; }
rm -f "$STATE_DIR/ready"     # remove first, so a failure below cannot re-trigger in a loop

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
STAMP=$(date +%Y%m%d-%H%M%S)
installed=()

# $1 = list name, $2 = file; returns 0 if every line is valid for that list
valid() {
  local re
  case $1 in
    telegram-ips) re='^([0-9]{1,3}\.){3}:$' ;;
    *)            re="^$IP:$1\$" ;;
  esac
  [ -s "$2" ] || return 1
  # count lines that match neither the list format nor the placeholder (grep -c reads
  # everything, so no SIGPIPE surprises under pipefail)
  local bad
  bad=$(grep -vE "$re" "$2" | grep -cvE "$PLACEHOLDER_RE")
  [ "$bad" -eq 0 ]
}

for name in $ALLOWED; do
  src="$STATE_DIR/pending/$name"
  [ -f "$src" ] && [ ! -L "$src" ] || continue
  # copy at most MAX_BYTES into a root-only dir, then work only on the copy
  head -c "$MAX_BYTES" -- "$src" > "$TMP/$name" || continue
  if ! valid "$name" "$TMP/$name"; then
    log "REJECT $name: invalid format, not installed"; continue
  fi
  if cmp -s "$TMP/$name" "$LISTS/$name"; then
    log "same   $name"; continue
  fi
  mkdir -p "$BACKUP_DIR"
  [ -f "$LISTS/$name" ] && cp -p -- "$LISTS/$name" "$BACKUP_DIR/$name.$STAMP"
  if install -o "${OWNER%%:*}" -g "${OWNER##*:}" -m 660 -- "$TMP/$name" "$LISTS/$name"; then
    installed+=("$name")
    log "update $name ($(wc -l < "$TMP/$name") entries)"
  else
    log "ERROR  $name: install failed"
  fi
done
rm -rf "$STATE_DIR/pending"

[ "${#installed[@]}" -gt 0 ] || { log "no list changed"; exit 0; }

if ! "$ANALYSISD" -t; then
  log "ERROR configuration check failed, previous lists restored"
  for name in "${installed[@]}"; do
    if [ -f "$BACKUP_DIR/$name.$STAMP" ]; then
      cp -p -- "$BACKUP_DIR/$name.$STAMP" "$LISTS/$name"
    else
      rm -f -- "$LISTS/$name"
    fi
  done
  exit 1
fi

log "installed: ${installed[*]}. NOT restarting: the lists take effect at the next restart of wazuh-manager"
# keep the last 30 backups per list
for name in $ALLOWED; do
  ls -1t "$BACKUP_DIR/$name".* 2>/dev/null | tail -n +31 | xargs -r rm -f --
done
