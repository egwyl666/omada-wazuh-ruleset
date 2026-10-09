#!/usr/bin/env bash
# omada-ti-fetch.sh - OPTIONAL automatic update, part 1 of 2 (unprivileged, network).
#
# Downloads the threat-intel sources and builds CDB lists for the Omada ruleset:
#   ti-feodo-c2      abuse.ch Feodo Tracker, recommended list        (rule 100512)
#   ti-tor-relays    Tor Project Onionoo, all running relays         (rule 100513)
#   ti-mining-pools  pool domains from $POOLS_FILE resolved to IPv4  (rule 100514)
#   telegram-ips     core.telegram.org/resources/cidr.txt as /24     (rules 100701, 100711)
#
# Runs as the unprivileged user omada-ti (see omada-ti-fetch.service). It has NO access to
# Wazuh: it only writes to $STATE_DIR. Result: $STATE_DIR/pending/<list> and the flag file
# $STATE_DIR/ready, which starts omada-ti-apply.service (root, no network) via omada-ti-apply.path.
#
# A list whose source is broken (download error or too few entries) is left out; the list
# installed in Wazuh then stays as it is. Exit code 1 if any source failed (visible in systemd).
#
# Manual run for a test (writes into ./state, touches nothing else):
#   STATE_DIR=./state POOLS_FILE=../../docs/mining-pools.txt ./omada-ti-fetch.sh

set -uo pipefail

STATE_DIR=${STATE_DIR:-/var/lib/omada-ti}
POOLS_FILE=${POOLS_FILE:-/etc/omada-ti/mining-pools.txt}
FEODO_URL=${FEODO_URL:-https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt}
TOR_URL=${TOR_URL:-https://onionoo.torproject.org/summary?type=relay&running=true}
TELEGRAM_URL=${TELEGRAM_URL:-https://core.telegram.org/resources/cidr.txt}
# Lists to build; remove a name to stop updating that list automatically
FETCH_LISTS=${FETCH_LISTS:-ti-feodo-c2 ti-tor-relays ti-mining-pools telegram-ips}
# Pool IPs stay in the list for this many days after they were last resolved
POOLS_KEEP_DAYS=${POOLS_KEEP_DAYS:-30}
SEEN="$STATE_DIR/pools-seen"

IPRE='([0-9]{1,3}\.){3}[0-9]{1,3}'
# Cloudflare ranges: a pool behind the CDN would flag half the internet, so drop them
CF_RE='^(104\.(1[6-9]|2[0-7])\.|172\.(6[4-9]|7[01])\.|162\.15[89]\.|188\.114\.(9[6-9]|10[0-9]|11[01])\.|141\.101\.|108\.162\.|198\.41\.)'
PLACEHOLDER='0.0.0.0:placeholder-replace-me'
CURL=(curl -fsS --retry 2 --max-time 120)

log() { echo "$*"; }   # journald adds the timestamp
wanted() { case " $FETCH_LISTS " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

mkdir -p "$STATE_DIR" || exit 1
WORK=$(mktemp -d "$STATE_DIR/work.XXXXXX") || exit 1
chmod 755 "$WORK"
trap 'rm -rf "$WORK"' EXIT
built=0 failed=0

# $1 = list name, $2 = minimum entries, $3 = value after ':'; keys on stdin
make_list() {
  local name=$1 min=$2 val=$3 out="$WORK/$1" n
  sort -u | sed "s/\$/:$val/" > "$out"
  n=$(wc -l < "$out")
  if [ "$n" -lt "$min" ]; then
    log "WARN $name: only $n entries (min $min), source broken? list skipped"
    rm -f "$out"; failed=$((failed + 1)); return
  fi
  [ "$n" -eq 0 ] && echo "$PLACEHOLDER" > "$out"   # an empty CDB file is an error
  log "OK   $name: $n entries"
  built=$((built + 1))
}

# $1 = URL, $2 = output file
fetch() {
  if ! "${CURL[@]}" -o "$2" "$1"; then
    log "WARN download failed: $1"; failed=$((failed + 1)); return 1
  fi
}

if wanted ti-feodo-c2 && fetch "$FEODO_URL" "$WORK/feodo.raw"; then
  # The file has CRLF line endings: strip CR or no line matches ^IP$
  make_list ti-feodo-c2 0 ti-feodo-c2 < <(tr -d '\r' < "$WORK/feodo.raw" | grep -E "^$IPRE$")
fi

if wanted ti-tor-relays && fetch "$TOR_URL" "$WORK/tor.raw"; then
  make_list ti-tor-relays 1000 ti-tor-relays < <(grep -oE "$IPRE" "$WORK/tor.raw")
fi

if wanted ti-mining-pools; then
  if [ -r "$POOLS_FILE" ]; then
    grep -vE '^\s*(#|$)' "$POOLS_FILE" | tr -d '\r' | while read -r d; do
      getent ahostsv4 "$d" | awk '{print $1}'
    done | grep -E "^$IPRE$" | grep -vE "$CF_RE" | sort -u > "$WORK/pools.now"
    if [ -s "$WORK/pools.now" ]; then
      # Pool DNS is round-robin: every run returns a slightly different set of IPs, which would
      # change the list every night. Keep every IP seen in the last
      # POOLS_KEEP_DAYS days instead ("ip last-seen-epoch" in $SEEN).
      awk -v now="$(date +%s)" -v keep=$((POOLS_KEEP_DAYS * 86400)) -v seenf="$SEEN" '
        BEGIN { while ((getline l < seenf) > 0) { split(l, a, " "); seen[a[1]] = a[2] } }
        { seen[$1] = now }
        END { for (ip in seen) if (now - seen[ip] <= keep) print ip, seen[ip] }' \
        "$WORK/pools.now" | sort > "$WORK/pools.seen" && mv "$WORK/pools.seen" "$SEEN"
    fi
    make_list ti-mining-pools 1 ti-mining-pools < <(cut -d' ' -f1 "$SEEN" 2>/dev/null)
  else
    log "WARN $POOLS_FILE not readable, ti-mining-pools skipped"; failed=$((failed + 1))
  fi
fi

if wanted telegram-ips && fetch "$TELEGRAM_URL" "$WORK/telegram.raw"; then
  # IPv4 CIDR /16../24 -> one "a.b.c." prefix per /24 (format of lists/telegram-ips)
  make_list telegram-ips 10 "" < <(tr -d '\r' < "$WORK/telegram.raw" \
    | grep -E "^$IPRE/(1[6-9]|2[0-4])$" \
    | awk -F'[./]' '{n = 2 ^ (24 - $5); for (i = 0; i < n; i++) printf "%s.%s.%d.\n", $1, $2, $3 + i}')
fi

rm -f "$WORK"/*.raw

if [ "$built" -gt 0 ]; then
  rm -rf "$STATE_DIR/pending"
  mv "$WORK" "$STATE_DIR/pending" && trap - EXIT
  touch "$STATE_DIR/ready"
  log "published $built list(s) to $STATE_DIR/pending"
else
  log "nothing to publish"
fi

[ "$failed" -eq 0 ]
