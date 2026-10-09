# Omada -> Wazuh ruleset

[Українська версія: README_UA.md](README_UA.md)

Detection rules for **TP-Link Omada** (EAP access points / controller) client-traffic logs in **Wazuh SIEM**.
Omada logs one record per network flow. This project decodes those records and turns them into alerts:
suspicious ports, threat-intel hits, unknown devices, lateral movement from Wi-Fi, scans, off-hours remote access and more.

Repository layout:

| Path | What it is |
|---|---|
| `decoders/omada_decoders.xml` | Decoder: splits a log line into fields |
| `rules/omada_rules.xml` | 86 active rules (+ 1 disabled, 100505), IDs 100500-100850 |
| `lists/private-ips`, `lists/telegram-ips` | CDB lists: internal prefixes, Telegram subnets |
| `lists/known-macs`, `lists/known-aps` | CDB lists: your allowed client devices and access points (you fill them in; `known-aps` is optional) |
| `lists/mining-pools.txt` | Input for the script (mining pool domains); **not** a CDB list |
| `scripts/update_ti_lists.sh` | Builds the threat-intel CDB lists `ti-feodo-c2`, `ti-tor-relays`, `ti-mining-pools` |
| `docs/CHANGELOG_UA.md` | Change history (Ukrainian) |

> Important: the rules were written from reading the Omada log format. Before relying on them in production, run the checks from
> [section 10](#10-testing-with-wazuh-logtest) and [section 12](#12-limitations-and-what-to-verify-in-logtest) on your own manager.

---

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

## 2. Requirements

- **Wazuh manager 4.3 or newer** (the decoder uses PCRE2; correlation uses `same_field` / `different_*`).
- **Omada logs over syslog.** Configure the Omada controller / access points to send logs to a remote syslog server
  (the menu name differs between Omada versions, look for "remote logging" / "syslog server"). In this guide the syslog
  receiver is **rsyslog on the Wazuh manager**, writing to a file that Wazuh reads.
- For `update_ti_lists.sh` on the manager: `bash`, `curl`, `getent` (package `libc-bin`, normally present), root access, `systemctl`.
- The manager clock and timezone must be right (off-hours rules use manager local time).

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

Custom fields appear in alerts as `data.omada.src_mac`, `data.srcip`, `data.dstport`, etc.

## 4. Installation, step by step

Run on the Wazuh **manager**, as root. Paths are the defaults of a standard installation.

```bash
# 1. Decoder and rules
cp decoders/omada_decoders.xml /var/ossec/etc/decoders/
cp rules/omada_rules.xml       /var/ossec/etc/rules/

# 2. CDB lists (+ the pool domain list used by the script)
cp lists/private-ips lists/telegram-ips lists/known-macs lists/known-aps lists/mining-pools.txt /var/ossec/etc/lists/

# 3. Threat-intel script
cp scripts/update_ti_lists.sh /usr/local/bin/
chmod +x /usr/local/bin/update_ti_lists.sh

# 4. Generate ti-* lists once (no --restart yet)
/usr/local/bin/update_ti_lists.sh

# 5. Ownership
chown wazuh:wazuh /var/ossec/etc/decoders/omada_decoders.xml /var/ossec/etc/rules/omada_rules.xml
chown wazuh:wazuh /var/ossec/etc/lists/*
```

Step 6: register the lists in `/var/ossec/etc/ossec.conf`, **inside the existing `<ruleset>` block**
(do not add `mining-pools.txt`: it is not a CDB list):

```xml
<ruleset>
  <!-- ...existing entries... -->
  <list>etc/lists/private-ips</list>
  <list>etc/lists/telegram-ips</list>
  <list>etc/lists/known-macs</list>
  <list>etc/lists/known-aps</list>
  <list>etc/lists/ti-feodo-c2</list>
  <list>etc/lists/ti-tor-relays</list>
  <list>etc/lists/ti-mining-pools</list>
</ruleset>
```

Step 7: check the configuration and restart.

```bash
/var/ossec/bin/wazuh-analysisd -t        # config / rules test, must print no errors
systemctl restart wazuh-manager
```

The rule IDs 100500-100850 must not clash with your other custom rules; change them if they do.

## 5. Receiving the logs: rsyslog -> file -> Wazuh

### 5.1 rsyslog

Create `/etc/rsyslog.d/10-omada.conf`:

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

```bash
mkdir -p /var/log/omada
systemctl restart rsyslog
# the firewall must allow UDP/TCP 514 from the Omada controller / APs
```

Also add a logrotate rule for `/var/log/omada/omada.log` (otherwise the file grows without limit).

**The `#015#012` problem.** Omada may pack several records into one syslog message, separated by CR+LF.
By default rsyslog escapes control characters, so the separators become the literal text `#015#012` (octal 015 = CR, 012 = LF),
and Wazuh sees one giant line with many records glued together; only the first record is decoded.
`parser.escapeControlCharactersOnReceive="off"` stops the escaping, so the file gets real line breaks and every record
becomes its own line. After the change, `grep -c '#012' /var/log/omada/omada.log` must stop growing.

### 5.2 Wazuh `<localfile>`

In `/var/ossec/etc/ossec.conf` (on the machine where the file lives; for a separate syslog host install a Wazuh agent there):

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/omada/omada.log</location>
</localfile>
```

Restart afterwards: `systemctl restart wazuh-manager` (or `wazuh-agent`).

## 6. How to find everything you need

**Where are the Omada logs on the server?** It is the file you configured in rsyslog (`/var/log/omada/omada.log` above).
If someone else set it up, find it:

```bash
grep -rl 'AP MAC=' /var/log 2>/dev/null | head
```

**MACs of your own APs** (optional, only needed for rule 100505; see [section 8](#8-access-points-known-aps-and-rule-100505-optional-off-by-default)):

```bash
grep -oE 'AP MAC=[^ ]+' /var/log/omada/omada.log | sort | uniq -c
```

**MACs of client devices** (put the legitimate ones into `known-macs`):

```bash
grep -oE 'MAC SRC=[^ ]+' /var/log/omada/omada.log | sort | uniq -c
```

**CDB entry format.** One entry per line, MAC in double quotes (it contains colons), then `:` and a label:

```
"aa:bb:cc:dd:ee:ff":my-laptop
```

The MACs in the log are lower case; keep them lower case in the lists (lookup is case-sensitive).
A CDB file must not be empty. `known-macs` and `known-aps` ship with a placeholder `"00:00:00:00:00:00":placeholder-replace-me`.

**Where are the files?**

| What | Path |
|---|---|
| Main config | `/var/ossec/etc/ossec.conf` |
| Custom rules | `/var/ossec/etc/rules/` |
| Custom decoders | `/var/ossec/etc/decoders/` |
| CDB lists | `/var/ossec/etc/lists/` |
| Manager log (errors on start) | `/var/ossec/logs/ossec.log` |
| Alerts (JSON) | `/var/ossec/logs/alerts/alerts.json` |

**Manager timezone** (needed for the off-hours rules 100630-100633, which use manager local time and are written for `Europe/Kyiv`, formerly `Europe/Kiev`):

```bash
timedatectl | grep 'Time zone'
date
# change if needed:
timedatectl set-timezone Europe/Kyiv
systemctl restart wazuh-manager
```

**Where to see alerts.**

- Dashboard: *Threat Hunting / Security events*. Useful filters: `rule.groups: suspicious_port`, `threat_intel`, `inventory`, `new_device`,
  `off_hours`, `lateral`, `scan`, `p2p`, `remote_access`, `policy_violation`, `anomaly`, `app_gaming`, or `rule.id: 100506`.
  Filter by device: `data.omada.src_mac: "00:11:22:33:44:66"`.
- Command line:

```bash
tail -f /var/ossec/logs/alerts/alerts.json | jq -c 'select(.rule.id|startswith("1005") or startswith("1006"))'
jq -c 'select(.rule.groups|index("threat_intel")) | {t:.timestamp, id:.rule.id, src:.data.srcip, dst:.data.dstip}' /var/ossec/logs/alerts/alerts.json
```

Level 0 events never reach `alerts.json`. To see them, enable `<logall_json>yes</logall_json>` under `<global>` temporarily and read `archives.json`.

## 7. Threat intel

`update_ti_lists.sh` builds three CDB lists that rules 100512-100514 use. They are checked **before** the port rules.

| List | Source | Rule | Level |
|---|---|---|---|
| `ti-feodo-c2` | abuse.ch Feodo Tracker, "recommended" blocklist (botnet C2, low false positives, CC0) | 100512 | 12 |
| `ti-tor-relays` | Tor Project Onionoo API, all running relays (not only exits: clients connect to relays/guards) | 100513 | 10 |
| `ti-mining-pools` | domains from `mining-pools.txt`, resolved to IPs with `getent ahostsv4`; Cloudflare ranges are dropped (a pool behind a CDN would flag half the internet) | 100514 | 10 |

How the script works:

1. Downloads each source (`curl`, with time limits) and extracts IPv4 addresses; converts them to `IP:list-name` lines.
2. Sanity check: if a list ends up smaller than expected (Tor: fewer than 1000), the download is considered broken and the **old list is kept**.
3. Replaces a file only if the content changed (`cmp`), with owner `wazuh:wazuh`, mode 660 (variables `LISTS` and `OWNER` can be overridden).
4. With `--restart`, restarts `wazuh-manager` **only if something changed**.

Usage and cron. Create `/etc/cron.d/omada-ti`:

```
15 4 * * * root /usr/local/bin/update_ti_lists.sh --restart >> /var/log/update_ti_lists.log 2>&1
```

Add or remove mining pool domains in `/var/ossec/etc/lists/mining-pools.txt` (one per line, `#` for comments).

**Why restart, and why at night.** Wazuh compiles CDB lists only when the manager starts, so new content is not used until a restart.
A restart briefly stops event analysis and clears the in-memory counters of the correlation rules (scans, torrent, spambot, rates);
at night, with the least traffic, this costs the least. Do not run the script with `--restart` during working hours.

## 8. Access points (`known-aps`) and rule 100505: optional, off by default

**What `known-aps` is.** A whitelist of **access point** MACs: the value of `AP MAC=` in the log, i.e. the EAP that carried the client's traffic.
It is **not** a list of controllers. The Omada controller (software controller, OC200/OC300) only manages the APs and forwards their logs;
its own MAC never appears in `AP MAC=`, so you never put a controller into this list.

**Who uses it.** Only rule 100505 (rogue AP, level 10): "this flow went through an AP that is not in `known-aps`". No other rule reads the list.

**Is it working now? No, and nothing depends on it.** 100505 is commented out, so the list is not consulted. The repository ships
`known-aps` with a placeholder (`"00:00:00:00:00:00":placeholder-replace-me`) only so that the `<list>etc/lists/known-aps</list>` entry in
`ossec.conf` points to an existing, non-empty file. All other rules (ports, threat intel, new-device inventory 100506/100507,
correlation, off-hours) work without knowing a single AP. **Install everything as described in section 4 and leave `known-aps` as is.**

**Why it is off by default.** If 100505 were on with an empty or incomplete list, **every flow** through an "unknown" AP would match it.
Because only the first matching sibling rule wins (100505 is checked before the destination split), those flows would also stop
reaching the port and threat-intel rules. So enable it only when the list is complete, and add new APs to the list **before** they go live.

### Connecting your APs later

1. **Find the AP MACs.** Any of these works; you do not need access to the controller:
   - from the logs Wazuh already receives (one line per AP, the number is how many flows it carried):

     ```bash
     grep -oE 'AP MAC=[^ ]+' /var/log/omada/omada.log | sort | uniq -c
     ```

   - from the Omada controller UI, *Devices* list (MAC column), when you have access to it;
   - from the label on the AP itself.

   A MAC from the logs that you cannot match to a real AP is exactly what this rule is meant to catch: investigate it before adding it.

2. **Build the list.** Draft it from the logs, then give each AP a meaningful name and delete the placeholder line:

   ```bash
   grep -oE 'AP MAC=[^ ]+' /var/log/omada/omada.log | cut -d= -f2 | tr 'A-F' 'a-f' | sort -u \
     | awk '{printf "\"%s\":ap-%02d\n", $1, NR}' > /tmp/known-aps
   cat /tmp/known-aps
   ```

   Result (edit names by hand):

   ```
   "aa:bb:cc:dd:ee:01":office-floor1
   "aa:bb:cc:dd:ee:02":office-floor2
   ```

3. **Install the list:**

   ```bash
   cp /tmp/known-aps /var/ossec/etc/lists/known-aps
   chown wazuh:wazuh /var/ossec/etc/lists/known-aps
   ```

4. **Enable the rule.** The rule is wrapped in a comment whose first and last lines carry the marker `ENABLE-100505`. Delete those two lines:

   ```bash
   cp /var/ossec/etc/rules/omada_rules.xml /root/omada_rules.xml.bak
   sed -i '/ENABLE-100505/d' /var/ossec/etc/rules/omada_rules.xml
   ```

5. **Check and restart:** `/var/ossec/bin/wazuh-analysisd -t`, then `systemctl restart wazuh-manager`.

6. **Verify in `wazuh-logtest`:** a line with `AP MAC=` that is in `known-aps` must **not** give 100505; the same line with any other AP MAC
   must give 100505, level 10.

**Adding an AP later:** add its line to `known-aps`, `chown`, restart (lists are compiled at start), then bring the AP online.
**Disabling again:** restore the backup (`cp /root/omada_rules.xml.bak /var/ossec/etc/rules/omada_rules.xml`) or copy the file from this repository, then restart.

> Note: the flow logs used here were collected through an Omada controller. Whether APs in standalone mode (no controller) send the
> same `AP MAC=... MAC SRC=...` records was not verified. If `grep 'AP MAC=' /var/log/omada/omada.log` finds nothing, the decoder will not match.

## 9. First run: expect a burst of 100506 alerts

Rule 100506 (level 7) fires **once per MAC** that is not in `known-macs` ("first time seen" memory is stored by Wazuh in `/var/ossec/queue/fts/`).
Right after installation every device on your network is new, so you get **one alert per device**. This is normal.

What to do:

1. Let it run for a day or two.
2. Review the 100506/100507 alerts (or run the `MAC SRC=` command from section 6).
3. Add the devices you recognize to `known-macs`: `"aa:bb:cc:dd:ee:ff":name`.
4. `chown wazuh:wazuh /var/ossec/etc/lists/known-macs && systemctl restart wazuh-manager`.

From then on, only genuinely new devices alert. 100507 marks devices with a **randomized (locally administered) MAC**
(second hex character 2, 6, a or e), typical for phones with "private Wi-Fi address"; those are hard to attribute.

Note: the very first flow of a new MAC is matched by 100506 and therefore does not go through the port rules. All later flows do.

## 10. Testing with wazuh-logtest

```bash
/var/ossec/bin/wazuh-logtest -v
```

Paste a line, press Enter, read `Phase 3` (the rule that matched). First put the test client `00:11:22:33:44:66` into `known-macs`
(otherwise you will see 100506 first), restart the manager, and use these lines. Expected results are derived from reading the rules;
confirm them on your manager.

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
To test threat intel, temporarily add `198.51.100.99:test` to `/var/ossec/etc/lists/ti-feodo-c2`, restart and send a flow with `IP DST=198.51.100.99` -> 100512, level 12. Remove it afterwards.

## 11. Tuning and false positives

- **Games and media.** Rules 100730-100743 and 100850 are informational (level 3-5) and exist so you can see who plays/streams.
  If the noise bothers you, lower the `level` to 0 or move the rule out of the file.
- **Ports are shared.** The "suspicious port" rules mean "often used by", not "is". Typical offenders: 9001 (Tor, but also Portainer and other services,
  level 10), 9999 / 7777 / 5555 (mining stratum, but also game servers and Android ADB, level 10), 8000-8011 (Parsec, but also dev web servers, level 7),
  9000 (Webex media, but also many dev tools), 7000 (IRC alt, but also AirPlay / Cassandra).
- **Suppress a known-good case** by adding a rule that overrides the noisy one, for example in `/var/ossec/etc/rules/local_rules.xml`:

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
- **Telegram** subnets come from https://core.telegram.org/resources/cidr.txt; refresh `telegram-ips` from time to time.

## 12. Limitations and what to verify in logtest

Limitations:

- The log has **no byte counters** and **no allow/deny** verdict: you cannot see data volume or whether the firewall blocked the flow.
- A **port is not an application.** Port rules say "often used by X". Anything can run on 443 or 51413.
- **Tor bridges are not detected.** Only public relays from Onionoo are in the list; bridges are private by design.
- Threat-intel lists are only as fresh as the last run of the script, and a CDN-hosted pool or a shared IP can cause false positives.
- Omada logs the flow, not the content: a hit is a lead for investigation, not proof of compromise.

Verify these in `wazuh-logtest` (they depend on the Wazuh version) before trusting the rules:

1. **FTS on a dynamic field.** The decoder uses `<fts>omada.src_mac</fts>` on both `omada-flow` children. Send a line with an unknown MAC twice in one
   logtest session: the first must give 100506/100507, the second must not.
2. **Both child decoders run.** For a line **with** the `[epoch]` prefix, Phase 2 must show `omada.epoch` **and** `omada.ap_mac`, `srcip`, `dstport`, etc.
   If only one set is extracted, the same-name child decoders do not both execute on your version.
3. **`negate` on `dstport`** in the frequency rule 100620 (200+ events per minute, excluding 80, 443, 53, 123).
4. **`same_*` / `different_*` / `same_field`** in the correlation rules 100600-100604, 100850 (generate test traffic: 25+ ports in 60 s must give 100600).
5. **CDB prefix lookup.** `address_match_key` with entries like `10.:` / `192.168.:` must treat `10.1.2.3` as internal. If your version only accepts
   full IPs/CIDR, rewrite `private-ips` and `telegram-ips` in CIDR form (`10.0.0.0/8:` etc.).
6. **Level 0 events in correlation.** Rules 100600, 100620, 100621 count the `omada` group, which includes level 0 events. Confirm that they are counted.

## 13. Troubleshooting

**The rule does not fire.**

1. Is the log reaching Wazuh? `tail -f /var/log/omada/omada.log` and `grep omada /var/ossec/logs/ossec.log`.
2. Does the line decode? Paste it into `wazuh-logtest -v`. If Phase 2 shows no decoder `omada`, check that records really are one per line
   (section 5, `#012`) and that the line does not start with a space: check with `head -3 /var/log/omada/omada.log | cat -A`; a leading space breaks `^\[` of the epoch decoder.
3. Is the rule level 0? Level 0 rules never alert; see the level in the table above.
4. Did you hit a **different** rule first? Only the first matching sibling rule wins; for example an unknown MAC gives 100506, and 100630 replaces 100530 at night.
5. First-seen memory: a MAC already seen does not trigger 100506 again; to re-test, use a new MAC.

**A list is not picked up.**

- It must be registered with `<list>` in `ossec.conf` inside `<ruleset>`, with the path `etc/lists/<name>` (no extension).
- Ownership: `chown wazuh:wazuh /var/ossec/etc/lists/*`.
- Format: one `key:value` per line, quoted MAC keys, no empty file, no merged lines (a missing line break once merged `172.31.:` and `192.168.:`).
- Lists are compiled on start: `systemctl restart wazuh-manager`. Check `grep -i cdb /var/ossec/logs/ossec.log`.
- `ti-*` files do not exist until you run `update_ti_lists.sh` once. A rule that references a missing list can stop the manager from starting.

**Errors at manager start.**

```bash
/var/ossec/bin/wazuh-analysisd -t
tail -50 /var/ossec/logs/ossec.log
```

- `Invalid ... XML` / `Syntax error`: a broken comment or tag, for example only one of the two `ENABLE-100505` lines deleted (see section 8).
- `Rule ID ... already exists` / `Duplicate`: your other custom rules use the same IDs; renumber.
- `Could not open CDB ...` / `list not found`: the file name in `<list>` or in the rule differs from the real file, or the file is not readable by `wazuh`.
- `Invalid element in the configuration`: the `<list>` lines are outside `<ruleset>`.
- Script problems: `tail /var/log/update_ti_lists.log`; `WARN ... keeping old list` means a download failed or a list was suspiciously small.
