#!/usr/bin/env bash
# update_ti_lists.sh – refresh threat-intel CDB lists for Wazuh (Omada rules 100512-100514)
#
#   ti-feodo-c2      abuse.ch Feodo Tracker, recommended list (botnet C2, low FP)
#   ti-tor-relays    all running Tor relays (Tor Project Onionoo API)
#                    NOTE: relays, not just exits – clients connect to relays/guards
#   ti-mining-pools  IPs of mining pool domains from mining-pools.txt
#
# Usage:   update_ti_lists.sh            # update lists only
#          update_ti_lists.sh --restart  # + restart wazuh-manager if something changed
# Cron:    15 4 * * * root /usr/local/bin/update_ti_lists.sh --restart >> /var/log/update_ti_lists.log 2>&1
#
# Needs: bash, curl, getent. Run as root on the Wazuh manager.

set -uo pipefail

LISTS=${LISTS:-/var/ossec/etc/lists}
POOLS_FILE="$LISTS/mining-pools.txt"
OWNER=${OWNER:-wazuh:wazuh}                      # older Wazuh (<4.3): ossec:ossec
IPRE='([0-9]{1,3}\.){3}[0-9]{1,3}'
# Cloudflare ranges – pools behind CDN would flag half the internet, so skip them
CDN_RE='^(104\.(1[6-9]|2[0-7])\.|172\.(6[4-9]|7[01])\.|162\.15[89]\.|188\.114\.(9[6-9]|10[0-9]|11[01])\.|141\.101\.|108\.162\.|198\.41\.)'

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
changed=0

log() { echo "$(date '+%F %T') $*"; }

# $1 = list name, $2 = file with IPs (one per line), $3 = min entries (sanity check)
install_list() {
  local name=$1 src=$2 min=$3 out="$TMP/$1.cdb" n
  grep -oE "^$IPRE$" "$src" | sort -u | sed "s/\$/:$name/" > "$out"
  n=$(wc -l < "$out")
  if [ "$n" -lt "$min" ]; then
    log "WARN $name: only $n entries (min $min) – download broken? keeping old list"
    return
  fi
  [ "$n" -eq 0 ] && echo "0.0.0.0:empty" > "$out"   # Wazuh dislikes empty CDB files
  if ! cmp -s "$out" "$LISTS/$name"; then
    install -o "${OWNER%%:*}" -g "${OWNER##*:}" -m 660 "$out" "$LISTS/$name"
    changed=1
    log "updated $name ($n entries)"
  else
    log "no change $name ($n entries)"
  fi
}

# --- Feodo Tracker (abuse.ch, CC0) ---
if curl -fsS --max-time 60 https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt \
     | grep -v '^#' > "$TMP/feodo.txt"; then
  install_list ti-feodo-c2 "$TMP/feodo.txt" 0
else
  log "WARN feodo download failed – keeping old list"
fi

# --- Tor relays (Onionoo) ---
if curl -fsS --max-time 120 'https://onionoo.torproject.org/summary?type=relay&running=true' \
     | grep -oE "$IPRE" > "$TMP/tor.txt"; then
  install_list ti-tor-relays "$TMP/tor.txt" 1000
else
  log "WARN tor download failed – keeping old list"
fi

# --- Mining pools (resolve domains) ---
if [ -f "$POOLS_FILE" ]; then
  grep -vE '^\s*(#|$)' "$POOLS_FILE" | while read -r d; do
    getent ahostsv4 "$d" | awk '{print $1}'
  done | grep -vE "$CDN_RE" > "$TMP/pools.txt"
  install_list ti-mining-pools "$TMP/pools.txt" 1
else
  log "WARN $POOLS_FILE not found – skipping mining pools"
fi

# --- Apply ---
if [ "$changed" -eq 1 ] && [ "${1:-}" = "--restart" ]; then
  log "lists changed – restarting wazuh-manager"
  systemctl restart wazuh-manager
fi
