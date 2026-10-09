# Omada -> Wazuh ruleset

[Українська версія: README_UA.md](README_UA.md)

Detection rules for **TP-Link Omada** (EAP access points / controller) client-traffic logs in **Wazuh SIEM**.
Omada logs one record per network flow. This project decodes those records and turns them into alerts:
suspicious ports, threat-intel hits, unknown devices, lateral movement from Wi-Fi, scans, off-hours remote access and more.

This guide is written for a **SOC analyst with limited access**: you work in the **Wazuh dashboard** and everything on the servers
(Omada, rsyslog, the Wazuh manager's OS) is done **by request** to the teams that own it. Ready-to-send request texts are in
[Appendix A](#appendix-a-request-templates). **No scripts are required**: every step is either a UI action or a request.
An optional automatic update of the threat-intel lists, installed once by an admin, is in `optional/ti-auto-update/` ([section 7.4](#74-optional-automatic-update-installed-once-by-an-admin)).

Repository layout:

| Path | What it is |
|---|---|
| `decoders/omada_decoders.xml` | Decoder: splits a log line into fields |
| `rules/omada_rules.xml` | 86 active rules (+ 1 disabled, 100505), IDs 100500-100850 |
| `lists/private-ips`, `lists/telegram-ips` | CDB lists: internal prefixes, Telegram subnets |
| `lists/known-macs`, `lists/known-aps` | CDB lists: your allowed client devices and access points (you fill them in; `known-aps` is optional) |
| `lists/ti-feodo-c2`, `lists/ti-tor-relays`, `lists/ti-mining-pools` | CDB lists for threat intel. Ship as **placeholders**; you fill them in manually (section 7) |
| `docs/mining-pools.txt` | Reference list of mining pool domains used to build `ti-mining-pools`; **not** deployed to Wazuh |
| `docs/CHANGELOG_UA.md` | Change history (Ukrainian) |
| `optional/ti-auto-update/` | **Optional.** Two scripts and four systemd units that update the threat-intel lists automatically (section 7.4) |

Everything in `lists/` is deployed to the manager; nothing from `docs/` is; `optional/` only if you decide to use it.

> Important: the rules were written from reading the Omada log format. Before relying on them in production, run the checks from
> [section 10](#10-testing-the-rules) and [section 12](#12-limitations-and-what-to-verify-in-logtest).

---

## 0. Who does what

| Task | Who | How |
|---|---|---|
| Send Omada logs over syslog | Network team (owner of the Omada controller / APs) | Request A1 |
| Receive syslog, write it to a file, rotate it, open port 514 | Linux admin of the Wazuh manager | Request A2 |
| Make Wazuh read that file (`<localfile>`) | Wazuh admin, or you in the UI if your role may edit the configuration | Request A3 or section 4.1 |
| Upload decoder, rules, CDB lists; register lists; restart | You in the UI (if your role has ruleset permissions), otherwise the Wazuh admin | Section 4.1 or request A3 |
| Check / set the manager timezone | Wazuh / Linux admin | Request A4 |
| Fill `known-macs`, `known-aps`, threat-intel lists | You (prepare the content), then UI upload or request A5 | Sections 7-9 |
| Optional: automatic threat-intel update | Wazuh / Linux admin, once | Request A8, section 7.4 |
| Keep everything up to date | You, with UI or requests | Section 14 |
| Test rules | You | Dashboard *Ruleset Test* |
| Read alerts, tune rules | You | Dashboard |
| Raw log samples, manager logs for troubleshooting | Admin | Requests A6, A7 |

Dashboard menu names differ between Wazuh versions. In 4.8 and newer most items are under **Server management** (Rules, Decoders,
CDB lists, Settings, Ruleset Test); in 4.3-4.7 they are under **Management** and **Tools**. What you may do there depends on the
permissions of your dashboard role; ask the Wazuh admin which of them you have.

## 1. What it is and what it detects

Omada gives you source/destination IP, ports, protocol and the MACs of the client and of the AP. It does **not** give you
payload, bytes, URLs or an allow/deny verdict. So detection is based on **who talks to whom, on which port, how often and when**.

| Group | Rule IDs | Level | What it detects |
|---|---|---|---|
| Base | 100500 | 0 | Any decoded Omada flow (parent of everything) |
| Inventory | 100505 (off), 100506, 100507 | 10 / 7 / 7 | Unknown AP (disabled by default), new unknown device, new device with randomized MAC |
| Destination split | 100510, 100511 | 0 | External vs internal destination (via `private-ips`) |
| Threat intel | 100512-100514 | 12 / 10 / 10 | Destination is a known botnet C2 (Feodo), a Tor relay, or a mining pool |
| Anonymizers / C2 / miners (ports) | 100520-100524 | 10, 10, 10, 8, 6 | Tor, reverse shell/C2, mining stratum, IRC, SOCKS/HTTP proxy ports |
| Remote access (external) | 100530-100534 | 8, 8, 9, 4, 7 | Outbound RDP, VNC, Telnet, SSH, TeamViewer/AnyDesk/RustDesk |
| Risky protocols (external) | 100540-100545 | 9, 8, 5, 8, 7, 6 | SMB/NetBIOS/RPC, direct SMTP, FTP, TFTP, SNMP/LDAP, database ports to the internet |
| DNS bypass | 100550-100551 | 4, 5 | Direct DNS to external resolvers, DNS-over-TLS |
| VPN / tunnels | 100560 | 5 | OpenVPN, WireGuard, PPTP, L2TP, IPsec |
| P2P / torrent | 100570-100571 | 5 | BitTorrent destination / source ports |
| Lateral movement (internal) | 100590-100596 | 6, 6, 8, 6, 6, 7, 7 | Wi-Fi client to SMB, RDP, WinRM, RPC, VNC, Telnet, databases |
| Correlation | 100600-100604 | 10, 12, 8, 12, 10 | Port scan, internal sweep, confirmed torrenting, repeated C2/miner traffic, spambot |
| Rate anomalies | 100620-100621 | 7, 9 | 200+ / 1000+ events per minute to one dst:port |
| Off-hours | 100630-100633 | 10, 9, 8, 7 | Remote access / VPN at night (20:00-07:00) and on weekends: same event, higher level |
| Applications (external) | 100700-100754 | 0-7 | Web, Telegram, push, calls, games, streaming, sync, IoT, remote desktop. Mostly level 0-4 (visibility), 100754 is 7 |
| LAN noise (internal) | 100800-100806 | 0 (100805: 3) | DNS/DHCP/Kerberos, mDNS/SSDP, printing, AirPlay, internal web, SSH, Syncthing |
| App correlation | 100850 | 5 | Sustained gaming traffic from one device |

Level 0 rules produce no alert; they only classify the event so that other rules can build on it.
By default Wazuh only stores alerts of level 3 and above, so level 0-2 events are not visible in the dashboard.

## 2. Requirements

- **Wazuh 4.3 or newer** (the decoder uses PCRE2; correlation uses `same_field` / `different_*`). Ask the Wazuh admin for the version
  if the dashboard does not show it (usually in the menu, *About*).
- **Omada logs over syslog** delivered to a file that the Wazuh manager (or an agent) reads. See section 5 and requests A1-A3.
- **Dashboard permissions** for you, ideally: view alerts, *Ruleset Test*, edit rules / decoders / CDB lists, edit configuration, restart.
  Without the edit permissions, everything still works through request A3/A5.
- The manager clock and timezone must be right (off-hours rules use the manager's local time). Request A4.
- For the manual threat-intel update (section 7): a workstation with internet access and either a Unix-like shell (Linux, macOS, WSL)
  or PowerShell.

## 3. Example log and its fields

```
[1791521490.308231667] AP MAC=00:11:22:33:44:55 MAC SRC=00:11:22:33:44:66 IP SRC=192.0.2.40 IP DST=149.154.167.41 IP proto=6 SPT=55138 DPT=443
```

| Wazuh field | From | Example | Meaning |
|---|---|---|---|
| `omada.epoch` | `[...]` | `1791521490.308231667` | Unix timestamp with fraction. Optional: not every record has it |
| `omada.ap_mac` | `AP MAC=` | `00:11:22:33:44:55` | The access point that carried the traffic |
| `omada.src_mac` | `MAC SRC=` | `00:11:22:33:44:66` | The client device (this is the key for inventory and P2P correlation) |
| `srcip` | `IP SRC=` | `192.0.2.40` | Client IP |
| `dstip` | `IP DST=` | `149.154.167.41` | Destination IP |
| `protocol` | `IP proto=` | `6` | IP protocol number: 6 = TCP, 17 = UDP |
| `srcport` | `SPT=` | `55138` | Source port (usually ephemeral) |
| `dstport` | `DPT=` | `443` | Destination port; most rules key on this |

In the dashboard and in alerts these fields are `data.omada.src_mac`, `data.omada.ap_mac`, `data.srcip`, `data.dstip`, `data.dstport`, etc.

## 4. Installation

Do the log intake first (section 5): without logs nothing can be tested except in *Ruleset Test*.
The rule IDs 100500-100850 must not clash with other custom rules on your manager; check in the Rules page and renumber if they do.

### 4.1 Through the dashboard (your role can edit the ruleset)

1. **Decoder.** *Decoders* -> *Custom decoders* -> add / import file -> `omada_decoders.xml` (content from `decoders/`). Save.
2. **Rules.** *Rules* -> *Custom rules* -> add / import file -> `omada_rules.xml` (content from `rules/`). Save.
3. **CDB lists.** *CDB lists* -> add / import each file from `lists/`, **with exactly the same name** (no extension):
   `private-ips`, `telegram-ips`, `known-macs`, `known-aps`, `ti-feodo-c2`, `ti-tor-relays`, `ti-mining-pools`.
   After saving, open each list and check that the lines look exactly as in the repository (for MAC lists: `"aa:bb:cc:dd:ee:ff":name`, with quotes).
4. **Register the lists.** Open the manager configuration (*Settings* -> *Edit configuration*, `ossec.conf`) and make sure these lines are
   **inside the existing `<ruleset>` block**. The dashboard does not always add them when you create a list:

   ```xml
   <list>etc/lists/private-ips</list>
   <list>etc/lists/telegram-ips</list>
   <list>etc/lists/known-macs</list>
   <list>etc/lists/known-aps</list>
   <list>etc/lists/ti-feodo-c2</list>
   <list>etc/lists/ti-tor-relays</list>
   <list>etc/lists/ti-mining-pools</list>
   ```

5. **Log source.** In the same configuration, add the `<localfile>` block from section 5.2 (if the Linux admin has not already).
6. **Restart** the manager from the dashboard (it offers a restart after saving, or use the restart button on the configuration / status page).
   The dashboard validates the configuration before restarting; if it reports an error, fix it first.
   A restart pauses analysis for a short time; coordinate the moment with your team.
7. **Test** in *Ruleset Test* (section 10).

Files saved through the dashboard get the right owner automatically; no `chown` is needed.

### 4.2 Through a request (no edit permissions)

Send **request A3** with the repository (or a zip of it) attached. It contains the exact commands for the admin.
Then test in *Ruleset Test* (section 10).

## 5. Receiving the logs: Omada -> rsyslog -> file -> Wazuh

This part is done by other teams: **A1** for the network team, **A2** for the Linux admin, and the `<localfile>` part of **A3**.
The configurations below are what you attach to those requests.

### 5.1 rsyslog on the Wazuh manager

`/etc/rsyslog.d/10-omada.conf`:

```
# Do NOT turn control characters into #015 / #012 (see below)
global(parser.escapeControlCharactersOnReceive="off")

module(load="imudp")
input(type="imudp" port="514" ruleset="omada")
# For TCP instead/in addition:
# module(load="imtcp")
# input(type="imtcp" port="514" ruleset="omada")

template(name="omada_raw" type="string" string="%msg%\n")

ruleset(name="omada") {
    action(type="omfile" file="/var/log/omada/omada.log" template="omada_raw")
    stop
}
```

Plus: `mkdir -p /var/log/omada`, `systemctl restart rsyslog`, firewall open for UDP/TCP 514 from the Omada controller / APs,
and a logrotate rule for `/var/log/omada/omada.log`.

**The `#015#012` problem.** Omada may pack several records into one syslog message, separated by CR+LF.
By default rsyslog escapes control characters, so the separators become the literal text `#015#012` (octal 015 = CR, 012 = LF),
and Wazuh sees one giant line with many records glued together; only the first record is decoded.
`parser.escapeControlCharactersOnReceive="off"` stops the escaping, so the file gets real line breaks and every record
becomes its own line. You can recognise the problem in the dashboard: far fewer Omada events than expected, and in *Ruleset Test* a
sample line from the admin contains `#012`.

### 5.2 Wazuh `<localfile>`

In `ossec.conf` of the manager (or of the agent on the host where the file is):

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/omada/omada.log</location>
</localfile>
```

Then restart.

## 6. How to find everything you need

**Are Omada events arriving?** In the dashboard (*Threat Hunting* / *Discover*), query `rule.groups: omada` over the last hour.
Because only level 3+ is stored, you will see Telegram, remote access, new devices etc., not every flow. If you see nothing at all after
a working day, check with request A6 that the file is being written and A7 for errors.

**MACs of your client devices** (for `known-macs`):

- every new device produces one 100506/100507 alert, so query `rule.id: (100506 or 100507)` and build a table
  (*Visualize* -> *Data table*, split rows by *Terms* on `data.omada.src_mac`, size 500; add `data.srcip` and `data.omada.ap_mac` as columns);
- or ask for the full list from the raw log with **request A6**.

**MACs of your own APs** (optional, only needed for rule 100505; see [section 8](#8-access-points-known-aps-and-rule-100505-optional-off-by-default)):
the same table with *Terms* on `data.omada.ap_mac` over `rule.groups: omada`, or request A6.

**CDB entry format.** One entry per line, MAC in double quotes (it contains colons), then `:` and a label:

```
"aa:bb:cc:dd:ee:ff":my-laptop
```

The MACs in the log are lower case; keep them lower case in the lists (lookup is case-sensitive).
A CDB file must not be empty. `known-macs`, `known-aps` and the `ti-*` lists ship with a placeholder line.

**Where the files live on the manager** (for requests and for the admin; in the dashboard you see the same files by name):

| What | Path |
|---|---|
| Main config | `/var/ossec/etc/ossec.conf` |
| Custom rules | `/var/ossec/etc/rules/` |
| Custom decoders | `/var/ossec/etc/decoders/` |
| CDB lists | `/var/ossec/etc/lists/` |
| Manager log (errors on start) | `/var/ossec/logs/ossec.log` |
| Alerts (JSON) | `/var/ossec/logs/alerts/alerts.json` |

**Manager timezone.** Off-hours rules 100630-100633 use the manager's local time and are written for `Europe/Kyiv` (formerly `Europe/Kiev`).
You cannot see it in the dashboard reliably; ask with **request A4**.

**Where to see alerts.** Dashboard, *Threat Hunting* / *Security events*. Useful filters:
`rule.groups: suspicious_port`, `threat_intel`, `inventory`, `new_device`, `off_hours`, `lateral`, `scan`, `p2p`, `remote_access`,
`policy_violation`, `anomaly`, `app_gaming`, or `rule.id: 100506`. Filter by device: `data.omada.src_mac: "00:11:22:33:44:66"`.

## 7. Threat intel: manual update (default) or automatic (optional)

Rules 100512-100514 check the destination IP against three CDB lists **before** the port rules.
The lists ship as placeholders (`0.0.0.0:placeholder-replace-me`), so the rules load but never match until you fill them in.
Two ways to keep them filled: **manually** (7.1-7.3, needs nothing on the server) or **automatically** (7.4, an admin installs it once).

| List | Source | Rule | Level |
|---|---|---|---|
| `ti-feodo-c2` | abuse.ch Feodo Tracker, "recommended" blocklist (botnet C2, low false positives, CC0): https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt | 100512 | 12 |
| `ti-tor-relays` | Tor Project Onionoo, all running relays (not only exits: clients connect to relays/guards): https://onionoo.torproject.org/summary?type=relay&running=true | 100513 | 10 |
| `ti-mining-pools` | domains from `docs/mining-pools.txt`, resolved to IPv4; Cloudflare ranges dropped (a pool behind a CDN would flag half the internet) | 100514 | 10 |

### 7.1 Build the files on your workstation

Every line must be `IP:list-name`, LF line endings, no empty file. Run in an empty folder; copy `docs/mining-pools.txt` there first.

**Linux / macOS / WSL** (needs `curl`, `grep`, `sed`; for pools `getent` on Linux or `dig` elsewhere):

```bash
IPRE='([0-9]{1,3}\.){3}[0-9]{1,3}'

# Feodo. The file has CRLF line endings: tr -d '\r' is required, otherwise no IP matches.
curl -fsS https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt | tr -d '\r' \
  | grep -E "^$IPRE$" | sort -u | sed 's/$/:ti-feodo-c2/' > ti-feodo-c2

# Tor relays (IPv4 only)
curl -fsS 'https://onionoo.torproject.org/summary?type=relay&running=true' \
  | grep -oE "$IPRE" | sort -u | sed 's/$/:ti-tor-relays/' > ti-tor-relays

# Mining pools (on macOS replace the getent line with: dig +short A "$d")
CF='^(104\.(1[6-9]|2[0-7])\.|172\.(6[4-9]|7[01])\.|162\.15[89]\.|188\.114\.(9[6-9]|10[0-9]|11[01])\.|141\.101\.|108\.162\.|198\.41\.)'
grep -vE '^\s*(#|$)' mining-pools.txt | while read -r d; do
  getent ahostsv4 "$d" | awk '{print $1}'
done | grep -E "^$IPRE$" | grep -vE "$CF" | sort -u | sed 's/$/:ti-mining-pools/' > ti-mining-pools

wc -l ti-*
```

**Windows PowerShell** (same result; not tested in this repository, so check the output as in 7.2):

```powershell
$ipre = '^\d{1,3}(\.\d{1,3}){3}$'
function Save-Cdb($name, $ips) {
  $lines = $ips | Where-Object { $_ -match $ipre } | Sort-Object -Unique | ForEach-Object { "$($_):$name" }
  if (-not $lines) { $lines = @('0.0.0.0:placeholder-replace-me') }
  [IO.File]::WriteAllText("$PWD\$name", (($lines -join "`n") + "`n"))   # LF endings
}

$feodo = (Invoke-WebRequest -UseBasicParsing 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt').Content -split "`r?`n"
Save-Cdb 'ti-feodo-c2' $feodo

$tor = (Invoke-RestMethod 'https://onionoo.torproject.org/summary?type=relay&running=true').relays | ForEach-Object { $_.a }
Save-Cdb 'ti-tor-relays' $tor

$cf = '^(104\.(1[6-9]|2[0-7])\.|172\.(6[4-9]|7[01])\.|162\.15[89]\.|188\.114\.(9[6-9]|10[0-9]|11[01])\.|141\.101\.|108\.162\.|198\.41\.)'
$pools = Get-Content .\mining-pools.txt | Where-Object { $_ -notmatch '^\s*(#|$)' } | ForEach-Object {
  Resolve-DnsName $_ -Type A -ErrorAction SilentlyContinue | Where-Object Type -eq 'A' | ForEach-Object IPAddress
} | Where-Object { $_ -notmatch $cf }
Save-Cdb 'ti-mining-pools' $pools
```

### 7.2 Check before uploading

- `ti-tor-relays` should have **thousands** of lines (about 6-8 thousand). A few dozen means the download broke: do not upload, keep the old list.
- `ti-feodo-c2` is small by nature (sometimes one or two lines). Open the source in a browser and look at `Last updated` in its header:
  if it is months old, the feed is stale and this list adds little; consider whether it is worth maintaining.
- `ti-mining-pools`: tens of lines. If it is empty, DNS resolution failed (corporate DNS may block pool domains; ask for an exception or resolve elsewhere).
- If a file came out empty, put the placeholder line `0.0.0.0:placeholder-replace-me` in it: an empty CDB file is an error.
- Lines must look like `198.51.100.7:ti-tor-relays`: no spaces, no headers.

### 7.3 Upload and apply

- **Dashboard:** *CDB lists* -> open the list -> replace its content (or import the file with the same name) -> save -> restart.
- **No permissions:** send **request A5** with the files attached.

Wazuh compiles CDB lists only when the manager starts, so **new content is used only after a restart**. A restart briefly stops
event analysis and clears the in-memory counters of the correlation rules (scans, torrent, spambot, rates). Combine list updates
(threat intel, `known-macs`, `known-aps`) into one restart in an agreed quiet window.

Suggested rhythm: Tor and Feodo every week or two, pools monthly or when you change `docs/mining-pools.txt`. Stale lists mostly cause
missed detections; Tor relays change constantly, so an old Tor list also gives some false positives on IPs that were reused.

### 7.4 Optional: automatic update (installed once by an admin)

If you do not want to repeat 7.1-7.3, ask the admin to install the files from `optional/ti-auto-update/` (**request A8**).
It is not required: the ruleset works the same without it. It updates `ti-feodo-c2`, `ti-tor-relays`, `ti-mining-pools` and
`telegram-ips`, and never touches `known-macs`, `known-aps`, `private-ips`, rules or decoders.

**How it works: two parts with the least privileges each.**

| Unit | Runs as | Network | Can write to | What it does |
|---|---|---|---|---|
| `omada-ti-fetch.timer` | systemd | | | Every night at 04:15 (+ up to 10 min random delay) starts the fetch part |
| `omada-ti-fetch.service` -> `omada-ti-fetch.sh` | dedicated user `omada-ti`, no capabilities, read-only system | yes | only `/var/lib/omada-ti` | Downloads Feodo, Tor, Telegram, resolves pool domains, checks sizes, writes the prepared lists and a flag file `ready` |
| `omada-ti-apply.path` | systemd | | | Starts the apply part as soon as `ready` appears |
| `omada-ti-apply.service` -> `omada-ti-apply.sh` | root | **no** (`PrivateNetwork`) | `/var/ossec/etc/lists`, `/var/lib/omada-ti`, `/var/backups/omada-ti` (+ Wazuh runtime dirs for the config check) | Strictly validates every prepared list, installs only the changed ones (with a backup), runs `wazuh-analysisd -t`; if the check fails, restores the backups. **Never restarts `wazuh-manager`** |

The code that talks to the internet never runs with privileges and cannot touch Wazuh; the root part never talks to the network and
accepts only files that look exactly like CDB lists of IPs (anything else is rejected and logged).

**Behaviour you should know about:**

- A broken source (download error, Tor below 1000 entries, no pool resolved) is skipped: the list installed in Wazuh stays as it was,
  and the fetch unit ends as *failed*, so the admin's monitoring can see it.
- **It never restarts `wazuh-manager`.** Wazuh compiles CDB lists only at start, so the updated files take effect at the
  **next restart of the manager**, whenever the admin does one (planned maintenance, an update of rules or lists, a reboot).
  Until then Wazuh keeps using the lists it loaded at its last start. If the manager is almost never restarted, agree on a
  regular restart window with the admin (for example weekly), otherwise the automatic update brings little.
- Pool DNS is round-robin and returns a different subset of IPs on every query. To keep the list stable, a pool IP
  stays in the list for 30 days after it was last resolved (`POOLS_KEEP_DAYS`).
- `Persistent=false`: if the server was off at 04:15, that run is simply skipped.
- It overwrites `telegram-ips`. If you maintain that list by hand, remove it from `FETCH_LISTS` (see settings).

**Installation (admin, as root, from the repository root):**

```bash
# 1. Dedicated system user without login or home
useradd --system --no-create-home --home-dir /var/lib/omada-ti --shell /usr/sbin/nologin omada-ti

# 2. Scripts (owned by root, NOT writable by omada-ti), pool domain list, backup dir
install -d -m 0755 /usr/local/libexec/omada-ti /etc/omada-ti
install -m 0755 optional/ti-auto-update/omada-ti-fetch.sh optional/ti-auto-update/omada-ti-apply.sh /usr/local/libexec/omada-ti/
install -m 0644 docs/mining-pools.txt /etc/omada-ti/mining-pools.txt
install -d -m 0700 /var/backups/omada-ti

# 3. Units
install -m 0644 optional/ti-auto-update/omada-ti-fetch.service optional/ti-auto-update/omada-ti-fetch.timer \
                optional/ti-auto-update/omada-ti-apply.path optional/ti-auto-update/omada-ti-apply.service /etc/systemd/system/
systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/omada-ti-fetch.service /etc/systemd/system/omada-ti-apply.service
systemctl enable --now omada-ti-apply.path omada-ti-fetch.timer

# 4. First run now (installs the lists, does not restart anything)
systemctl start omada-ti-fetch.service
journalctl -u omada-ti-fetch -u omada-ti-apply -n 50 --no-pager

# 5. Activate the lists: restart the manager once, in a quiet window
systemctl restart wazuh-manager
```

The scripts must stay owned by root and not writable by `omada-ti`; otherwise the unprivileged user could change what root runs.

**Checking that it works:**

```bash
systemctl list-timers 'omada-ti*'                      # next run
systemctl status omada-ti-fetch omada-ti-apply         # last result
journalctl -u omada-ti-fetch -u omada-ti-apply --since yesterday
ls -l /var/ossec/etc/lists/ /var/backups/omada-ti/
```

Without server access you can still see it: in the dashboard open the CDB list `ti-tor-relays`; it must have thousands of lines and change from day to day
(the file changes nightly; Wazuh uses the new content after the next restart of the manager).

**Settings** (drop-ins, so the shipped files stay unchanged):

```bash
systemctl edit omada-ti-fetch.service
#   [Service]
#   Environment="FETCH_LISTS=ti-feodo-c2 ti-tor-relays ti-mining-pools"   # e.g. without telegram-ips
#   Environment=POOLS_KEEP_DAYS=30
#   Environment=https_proxy=http://proxy.example:3128                    # if the manager needs a proxy

systemctl edit omada-ti-fetch.timer
#   [Timer]
#   OnCalendar=
#   OnCalendar=Sun *-*-* 04:15                                            # weekly instead of nightly

systemctl edit omada-ti-apply.service
#   [Service]
#   Environment=OWNER=ossec:ossec                                         # only for Wazuh older than 4.3
```

Pool domains are read from `/etc/omada-ti/mining-pools.txt`; edit it there.

**Removal:**

```bash
systemctl disable --now omada-ti-fetch.timer omada-ti-apply.path
rm /etc/systemd/system/omada-ti-fetch.service /etc/systemd/system/omada-ti-fetch.timer \
   /etc/systemd/system/omada-ti-apply.path /etc/systemd/system/omada-ti-apply.service
systemctl daemon-reload
rm -r /usr/local/libexec/omada-ti /etc/omada-ti /var/lib/omada-ti /var/backups/omada-ti
userdel omada-ti
```

The lists stay as they were last installed; from then on update them manually (7.1-7.3).

> Tested: both scripts against the live sources and with stand-ins for `systemctl` / `wazuh-analysisd` (repeated runs, pool IP expiry,
> rejection of invalid files, rollback after a failed check); units checked with `systemd-analyze verify`. Not tested on a live Wazuh manager:
> if `wazuh-analysisd -t` fails with a permission error under the sandbox of `omada-ti-apply.service`, the journal shows the path; add it to
> `ReadWritePaths=` with `systemctl edit omada-ti-apply.service`.

## 8. Access points (`known-aps`) and rule 100505: optional, off by default

**What `known-aps` is.** A whitelist of **access point** MACs: the value of `AP MAC=` in the log, i.e. the EAP that carried the client's traffic.
It is **not** a list of controllers. The Omada controller (software controller, OC200/OC300) only manages the APs and forwards their logs;
its own MAC never appears in `AP MAC=`, so you never put a controller into this list.

**Who uses it.** Only rule 100505 (rogue AP, level 10): "this flow went through an AP that is not in `known-aps`". No other rule reads the list.

**Is it working now? No, and nothing depends on it.** 100505 is commented out, so the list is not consulted. It ships with a placeholder
only so that the `<list>etc/lists/known-aps</list>` entry points to an existing, non-empty file. All other rules work without knowing a
single AP. **Install everything and leave `known-aps` as is.**

**Why it is off by default.** If 100505 were on with an empty or incomplete list, **every flow** through an "unknown" AP would match it.
Because only the first matching sibling rule wins (100505 is checked before the destination split), those flows would also stop
reaching the port and threat-intel rules. So enable it only when the list is complete, and add new APs to the list **before** they go live.

### Connecting your APs later

1. **Find the AP MACs.** Any of these:
   - dashboard table with *Terms* on `data.omada.ap_mac` (section 6);
   - the Omada controller UI, *Devices* list (MAC column), if you or the network team have access;
   - request A6 (full list from the raw log, with the number of flows per AP).

   A MAC you cannot match to a real AP is exactly what this rule is meant to catch: investigate it before adding it.

2. **Write the list** (lower case, one AP per line, delete the placeholder line):

   ```
   "aa:bb:cc:dd:ee:01":office-floor1
   "aa:bb:cc:dd:ee:02":office-floor2
   ```

3. **Upload** it to the CDB list `known-aps` in the dashboard (or request A5).

4. **Enable the rule.** In the dashboard open the custom rule file `omada_rules.xml`. Rule 100505 is wrapped in a comment whose first and
   last lines contain the marker `ENABLE-100505`. Delete **both** of these lines (nothing else), save.
   Without edit permissions: request A5 asks the admin to run `sed -i '/ENABLE-100505/d' /var/ossec/etc/rules/omada_rules.xml`.

5. **Restart**, then check in *Ruleset Test*: a line with an `AP MAC=` that is in `known-aps` must **not** give 100505;
   the same line with any other AP MAC must give 100505, level 10.

**Adding an AP later:** add its line to `known-aps`, restart, then bring the AP online.
**Disabling again:** put the two marker lines back, or replace the rule file with the one from this repository, then restart.

> Note: the flow logs used here were collected through an Omada controller. Whether APs in standalone mode (no controller) send the
> same `AP MAC=... MAC SRC=...` records was not verified. If no Omada events arrive at all, check this first (request A6).

## 9. First run: expect a burst of 100506 alerts

Rule 100506 (level 7) fires **once per MAC** that is not in `known-macs` (Wazuh remembers "first time seen" MACs on the manager).
Right after installation every device on your network is new, so you get **one alert per device**. This is normal.

What to do:

1. Let it run for a day or two.
2. Build the device table from the 100506/100507 alerts (section 6).
3. Put the devices you recognize into `known-macs`: `"aa:bb:cc:dd:ee:ff":name`, and remove the placeholder line.
4. Upload the list and restart (section 7.3; combine with other list updates).

From then on, only genuinely new devices alert. 100507 marks devices with a **randomized (locally administered) MAC**
(second hex character 2, 6, a or e), typical for phones with "private Wi-Fi address"; those are hard to attribute.

Note: the very first flow of a new MAC is matched by 100506 and therefore does not go through the port rules. All later flows do.

## 10. Testing the rules

Use the dashboard tool **Ruleset Test** (*Server management* -> *Ruleset Test*, older versions *Tools* -> *Ruleset Test*). It is the same
engine as `wazuh-logtest` on the manager. Paste a line, run it, read the decoded fields (phase 2) and the matched rule (phase 3).

Before testing, put the test client `00:11:22:33:44:66` into `known-macs` (otherwise the first line gives 100506) and restart.
Expected results are derived from reading the rules; confirm them on your manager.

| # | What it tests | Line | Expected |
|---|---|---|---|
| 1 | Torrent | `[1791521490.308231667] AP MAC=00:11:22:33:44:55 MAC SRC=00:11:22:33:44:66 IP SRC=192.0.2.40 IP DST=198.51.100.10 IP proto=6 SPT=40000 DPT=51413` | 100570, level 5 |
| 2 | RDP to the internet | `[1791521491.100000000] AP MAC=00:11:22:33:44:55 MAC SRC=00:11:22:33:44:66 IP SRC=192.0.2.40 IP DST=198.51.100.20 IP proto=6 SPT=40001 DPT=3389` | 100530, level 8 (at night 100630, level 10; at weekends 100631, level 9) |
| 3 | Telegram | `[1791521492.100000000] AP MAC=00:11:22:33:44:55 MAC SRC=00:11:22:33:44:66 IP SRC=192.0.2.40 IP DST=149.154.167.41 IP proto=6 SPT=40002 DPT=443` | 100701, level 3 |
| 4 | Internal SMB | `[1791521493.100000000] AP MAC=00:11:22:33:44:55 MAC SRC=00:11:22:33:44:66 IP SRC=192.0.2.40 IP DST=192.168.10.20 IP proto=6 SPT=40003 DPT=445` | 100590, level 6 |
| 5 | Ordinary web | `[1791521494.100000000] AP MAC=00:11:22:33:44:55 MAC SRC=00:11:22:33:44:66 IP SRC=192.0.2.40 IP DST=198.51.100.30 IP proto=6 SPT=40004 DPT=443` | 100700, level 0 (no alert) |
| 6 | New device, randomized MAC | `[1791521495.100000000] AP MAC=00:11:22:33:44:55 MAC SRC=02:11:22:33:44:77 IP SRC=192.0.2.41 IP DST=198.51.100.30 IP proto=6 SPT=40005 DPT=443` | 100507, level 7 (second event with the same MAC in the same session: not 100506 again) |

Extra: `DPT=9001` to an external IP -> 100520 (Tor port, level 10); `IP proto=17 ... DPT=443` -> 100702 (QUIC, level 0).
Test 4 uses `192.168.10.20`, so it also proves that `192.168.` is treated as internal in `private-ips`.
To test threat intel, temporarily add `198.51.100.99:test` to `ti-feodo-c2`, restart and test a flow with `IP DST=198.51.100.99`
-> 100512, level 12. Remove it at the next list update.

## 11. Tuning and false positives

All of this is done by editing `omada_rules.xml` (or your own rule file) in the dashboard, or by request A5, followed by a restart.

- **Games and media.** Rules 100730-100743 and 100850 are informational (level 3-5) and exist so you can see who plays/streams.
  If the noise bothers you, lower the `level` to 0.
- **Ports are shared.** The "suspicious port" rules mean "often used by", not "is". Typical offenders: 9001 (Tor, but also Portainer and other services,
  level 10), 9999 / 7777 / 5555 (mining stratum, but also game servers and Android ADB, level 10), 8000-8011 (Parsec, but also dev web servers, level 7),
  9000 (Webex media, but also many dev tools), 7000 (IRC alt, but also AirPlay / Cassandra).
- **Suppress a known-good case** by adding a rule that overrides the noisy one, for example in the custom file `local_rules.xml`:

```xml
<rule id="100900" level="0">
  <if_sid>100522</if_sid>
  <field name="omada.src_mac">^00:11:22:33:44:66$</field>
  <description>Omada: ignore game server ports from the console 00:11:22:33:44:66</description>
</rule>
```

- **`ignore`.** `<rule ... ignore="600">` (as in 100505) suppresses repeats of an alert for N seconds. Use it on chatty rules.
- **Levels.** Change `level="N"` to fit your policy. Keep correlation rules above the rules they count.
- **Off-hours.** 100630-100633 re-alert the same event at a higher level for any rule in the `remote_access` / `vpn` groups, and the
  `remote_access` group also includes internal SSH (100805), so internal SSH at night will alert at level 10. Adjust or remove if that is not wanted.
  The time window `20:00 - 07:00` is hard-coded in the rules.
- **Internal ranges.** `private-ips` does not cover other multicast (`239.x`, e.g. SSDP) or CGNAT (`100.64.`). Add them if they bother you.
- **Telegram** subnets come from https://core.telegram.org/resources/cidr.txt; compare with `telegram-ips` from time to time.

## 12. Limitations and what to verify in logtest

Limitations:

- The log has **no byte counters** and **no allow/deny** verdict: you cannot see data volume or whether the firewall blocked the flow.
- A **port is not an application.** Port rules say "often used by X". Anything can run on 443 or 51413.
- **Tor bridges are not detected.** Only public relays from Onionoo are in the list; bridges are private by design.
- Threat-intel lists are only as fresh as their last update (manual or automatic).
- Omada logs the flow, not the content: a hit is a lead for investigation, not proof of compromise.

Verify these in *Ruleset Test* (they depend on the Wazuh version) before trusting the rules:

1. **FTS on a dynamic field.** The decoder uses `<fts>omada.src_mac</fts>` on both `omada-flow` children. Test a line with an unknown MAC twice in one
   session: the first must give 100506/100507, the second must not.
2. **Both child decoders run.** For a line **with** the `[epoch]` prefix, phase 2 must show `omada.epoch` **and** `omada.ap_mac`, `srcip`, `dstport`, etc.
   If only one set is extracted, the same-name child decoders do not both execute on your version.
3. **`negate` on `dstport`** in the frequency rule 100620 (200+ events per minute, excluding 80, 443, 53, 123).
4. **`same_*` / `different_*` / `same_field`** in the correlation rules 100600-100604, 100850. One-line tests cannot trigger them;
   watch for 100600 (port scan) after an authorised scan from a test device, coordinated with the network team.
5. **CDB prefix lookup.** `address_match_key` with entries like `10.:` / `192.168.:` must treat `10.1.2.3` as internal (tests 4 and 5).
   If your version only accepts full IPs/CIDR, rewrite `private-ips` and `telegram-ips` in CIDR form (`10.0.0.0/8:` etc.).
6. **Level 0 events in correlation.** Rules 100600, 100620, 100621 count the `omada` group, which includes level 0 events. Confirm that they are counted.

## 13. Troubleshooting

**No Omada events at all.**

1. Ask with **request A6** whether `/var/log/omada/omada.log` is being written and for a few sample lines.
2. Paste a sample line into *Ruleset Test*. If phase 2 shows no decoder `omada`: does the line contain `#012` (section 5.1)? Does it start
   with a space? A leading space breaks `^\[` of the epoch decoder; the admin can see it with `head -3 /var/log/omada/omada.log | cat -A`.
3. Check that the `<localfile>` block exists in the configuration (section 5.2).

**The rule does not fire.**

1. Is the rule level 0-2? Those never appear in the dashboard; see the level in the table above.
2. Did a **different** rule match first? Only the first matching sibling rule wins; for example an unknown MAC gives 100506, and 100630 replaces 100530 at night.
3. First-seen memory: a MAC already seen does not trigger 100506 again; to re-test, use a new MAC.
4. Threat-intel rules never fire while the `ti-*` lists contain only the placeholder (section 7).

**A list is not picked up.**

- It must be registered with `<list>` inside `<ruleset>` in `ossec.conf`, with the path `etc/lists/<name>` (no extension), and the
  list name in the dashboard must be exactly that name.
- Format: one `key:value` per line, quoted MAC keys, LF line endings, no empty file, no merged lines (a missing line break once merged `172.31.:` and `192.168.:`).
- Lists are compiled on start: was there a restart after the change?

**The manager does not restart / the dashboard reports a configuration error.** Ask with **request A7** for the validation output and the manager log. Typical causes:

- `Invalid ... XML` / `Syntax error`: a broken comment or tag, for example only one of the two `ENABLE-100505` lines deleted (section 8).
- `Rule ID ... already exists` / `Duplicate`: other custom rules use the same IDs; renumber.
- `Could not open CDB ...` / `list not found`: the name in `<list>` or in the rule differs from the real list name.
- `Invalid element in the configuration`: the `<list>` lines are outside `<ruleset>`.

**Automatic update (if installed) does not update the lists.** Ask the admin for
`journalctl -u omada-ti-fetch -u omada-ti-apply --since "2 days ago"`. `WARN download failed` means the manager cannot reach the source
(firewall / proxy); `REJECT` means a list had an unexpected format and was not installed; `configuration check failed` means the lists
were rolled back. `installed: ...` with no effect in alerts means the manager has not been restarted since.

## 14. Maintenance: updating everything manually

Everything here can be done without any script, through the dashboard or a request. Collect the changes and apply them with **one restart**
in an agreed quiet window: CDB lists are compiled only at start.

| What | Source | How often | How |
|---|---|---|---|
| `ti-feodo-c2`, `ti-tor-relays`, `ti-mining-pools` | Feodo, Onionoo, `docs/mining-pools.txt` | Every 1-2 weeks (pools monthly), or automatic (7.4) | Section 7.1-7.3 |
| `telegram-ips` | https://core.telegram.org/resources/cidr.txt | Every few months | Command below, then *CDB lists* or request A5 |
| `known-macs` | Your devices, new-device alerts 100506/100507 | When new legitimate devices appear | Section 9; *CDB lists* or A5 |
| `known-aps` (only if 100505 is on) | Your APs | Before an AP is added or replaced | Section 8 |
| `private-ips` | Your address plan | When the address plan changes | Edit list (`prefix.:` per line); *CDB lists* or A5 |
| `docs/mining-pools.txt` | Your own research | Occasionally | Edit, then rebuild `ti-mining-pools` (7.1); with auto-update edit `/etc/omada-ti/mining-pools.txt` (request A5) |
| Rules and decoder (new version of this repository) | This repository | When it changes | Replace the content of `omada_rules.xml` / `omada_decoders.xml` in *Rules* / *Decoders*, or A5 |
| Your own tuning | You | As needed | Keep it in a separate file such as `local_rules.xml` (section 11), so a new `omada_rules.xml` does not overwrite it |

**`telegram-ips` from the official CIDR list** (each IPv4 network /16-/24 becomes one `a.b.c.:` line per /24):

```bash
curl -fsS https://core.telegram.org/resources/cidr.txt | tr -d '\r' \
  | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}/(1[6-9]|2[0-4])$' \
  | awk -F'[./]' '{n=2^(24-$5); for(i=0;i<n;i++) printf "%s.%s.%d.:\n",$1,$2,$3+i}' | sort -u > telegram-ips
wc -l telegram-ips     # tens of lines; compare with the current list before uploading
```

PowerShell (not tested in this repository; check the result looks like `91.108.56.:`):

```powershell
$lines = (Invoke-WebRequest -UseBasicParsing 'https://core.telegram.org/resources/cidr.txt').Content -split "`r?`n" |
  ForEach-Object {
    $m = [regex]::Match($_, '^(\d+)\.(\d+)\.(\d+)\.\d+/(1[6-9]|2[0-4])$')
    if ($m.Success) {
      $n = [math]::Pow(2, 24 - [int]$m.Groups[4].Value)
      0..($n - 1) | ForEach-Object { '{0}.{1}.{2}.:' -f $m.Groups[1].Value, $m.Groups[2].Value, ([int]$m.Groups[3].Value + $_) }
    }
  } | Sort-Object -Unique
[IO.File]::WriteAllText("$PWD\telegram-ips", (($lines -join "`n") + "`n"))
```

**Do not publish your own lists.** `known-macs` and `known-aps` with real MACs (and a real `private-ips`) describe your network.
If you keep them under version control, use a private repository, not this public one.

---

## Appendix A. Request templates

Copy, fill in the `<...>` parts, attach what is listed.

**A1. Network team: send Omada logs to syslog**

> Please configure remote syslog on the Omada controller `<name/IP>` (and/or the access points of site `<site>`) to send logs to
> `<Wazuh manager IP>`, port 514, UDP (or TCP if supported). We need the client traffic records that look like
> `AP MAC=... MAC SRC=... IP SRC=... IP DST=... IP proto=... SPT=... DPT=...`. Purpose: security monitoring in Wazuh.
> Please tell us when it is done and which source IP the logs will come from.

**A2. Linux admin of the Wazuh manager: receive syslog into a file**

> On the Wazuh manager `<host>` please:
> 1. Create `/etc/rsyslog.d/10-omada.conf` with the attached content (section 5.1 of the README), `mkdir -p /var/log/omada`, `systemctl restart rsyslog`.
> 2. Allow UDP/TCP 514 from `<Omada source IP>` in the host firewall.
> 3. Add logrotate for `/var/log/omada/omada.log` (daily, keep 14, compress, `copytruncate` or reload rsyslog after rotation).
> 4. After the network team enables syslog, send us `head -5 /var/log/omada/omada.log | cat -A` to confirm the format.

**A3. Wazuh admin: install the Omada ruleset**

> Please install the attached Omada ruleset on the Wazuh manager `<host>`:
> ```
> cp decoders/omada_decoders.xml /var/ossec/etc/decoders/
> cp rules/omada_rules.xml /var/ossec/etc/rules/
> cp lists/* /var/ossec/etc/lists/
> chown wazuh:wazuh /var/ossec/etc/decoders/omada_decoders.xml /var/ossec/etc/rules/omada_rules.xml /var/ossec/etc/lists/*
> ```
> In `/var/ossec/etc/ossec.conf`, inside `<ruleset>`, add the seven `<list>` lines from README section 4.1, step 4.
> Add the `<localfile>` block from README section 5.2 for `/var/log/omada/omada.log`.
> Validate with `/var/ossec/bin/wazuh-analysisd -t`, then `systemctl restart wazuh-manager` in `<agreed window>`.
> Please check that rule IDs 100500-100850 are not used by other custom rules, and send us the output of the validation.

**A4. Wazuh / Linux admin: manager timezone**

> Please send the output of `timedatectl` on the Wazuh manager `<host>`. Our off-hours rules expect local time `Europe/Kyiv`.
> If it differs, please set it (`timedatectl set-timezone Europe/Kyiv`) and restart `wazuh-manager` in `<agreed window>`.

**A5. Wazuh admin: update lists / rule file**

> Please replace the following files on the Wazuh manager `<host>` with the attached ones: `/var/ossec/etc/lists/<names>`
> (and/or `/var/ossec/etc/rules/omada_rules.xml`), then `chown wazuh:wazuh` them, validate with `/var/ossec/bin/wazuh-analysisd -t`
> and restart `wazuh-manager` in `<agreed window>`.
> (To enable rule 100505 instead of replacing the rule file: `sed -i '/ENABLE-100505/d' /var/ossec/etc/rules/omada_rules.xml`.)

**A6. Linux admin: raw log samples and inventory**

> On `<host>` please send us the output of:
> ```
> ls -l /var/log/omada/
> head -5 /var/log/omada/omada.log | cat -A
> grep -c '#012' /var/log/omada/omada.log
> grep -oE 'AP MAC=[^ ]+' /var/log/omada/omada.log | sort | uniq -c
> grep -oE 'MAC SRC=[^ ]+' /var/log/omada/omada.log | sort | uniq -c | sort -rn
> ```

**A7. Wazuh admin: diagnostics**

> On the Wazuh manager `<host>` please send us the output of:
> ```
> /var/ossec/bin/wazuh-analysisd -t
> tail -100 /var/ossec/logs/ossec.log
> grep -iE 'cdb|list|omada' /var/ossec/logs/ossec.log | tail -50
> ls -l /var/ossec/etc/lists/
> ```

**A8. Wazuh / Linux admin: optional automatic threat-intel update**

> Please install the optional automatic threat-intel update for the Omada ruleset on the Wazuh manager `<host>`, following README
> section 7.4 (files in `optional/ti-auto-update/`). The download runs as an unprivileged user without access to Wazuh; the install step
> runs as root without network and validates the files; it never restarts `wazuh-manager`, so the lists take effect at the next
> planned restart of the manager. Please tell us how often the manager is restarted, or agree a regular restart window with us.
> The manager needs outbound HTTPS to `feodotracker.abuse.ch`, `onionoo.torproject.org`, `core.telegram.org` and DNS resolution of the
> domains in `docs/mining-pools.txt` (proxy, if required: `<proxy>`).
> Please do the first run and one restart of `wazuh-manager` in `<agreed window>`, send us `journalctl -u omada-ti-fetch -u omada-ti-apply -n 50 --no-pager`,
> and add `omada-ti-fetch.service` and `omada-ti-apply.service` to the monitoring of failed systemd units.
