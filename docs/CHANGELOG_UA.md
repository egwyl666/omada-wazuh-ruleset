# Omada → Wazuh: що змінилося

## v4 — TI, інвентаризація, аномалії

**Threat intel (100512–100514)** — перевірка IP призначення до правил по портах:
- Feodo C2 (abuse.ch) → level 12
- Tor relay-ноди (усі, не лише exit) → level 10
- майнінг-пули (домени з `mining-pools.txt`, резолвляться в IP) → level 10
- старі правила по портах лишились як запасний варіант

**`update_ti_lists.sh`** — оновлює TI-списки:
- качає Feodo і Tor, резолвить пули, збирає CDB-списки
- рестартує менеджер лише якщо щось змінилось (`--restart`)
- якщо завантаження зламалось — лишає старий список
- IP Cloudflare з пулів викидає

**Інвентаризація:**
- 100505 — rogue AP (AP не з `known-aps`). **Вимкнено за замовчуванням** (закоментовано). Щоб увімкнути: заповнити `known-aps` і прибрати коментар
- 100506 — новий невідомий пристрій (MAC не з `known-macs`), один раз на MAC через FTS → level 7
- 100507 — те саме, але MAC рандомізований

**Аномалії:**
- 100620 — 200+ подій/хв на один dst:port (крім web/DNS/NTP) → level 7
- 100621 — 1000+ подій/хв на будь-який порт → level 9

**Off-hours (100630–100633):** remote access і VPN вночі (20:00–07:00) та у вихідні → підвищений level

**Декодер:** додано `<fts>omada.src_mac</fts>`

**Нові файли:** `known-macs`, `known-aps`, `mining-pools.txt`, `update_ti_lists.sh`

## v3 — підозрілі порти
- 29 правил на ненадійних портах тепер пишуть «suspicious port … (often used by: X)» замість назви застосунку
- група `suspicious_port` для фільтрації

## v2 — порти застосунків
- 39 правил: месенджери, дзвінки, ігри, стрімінг, sync/IoT, LAN-шум
- Telegram — за офіційними IP-підмережами (`telegram-ips`)

## v1 — базове
- декодер Omada (AP MAC, MAC SRC, IP, порти, протокол, timestamp)
- поділ на зовнішній / внутрішній трафік (`private-ips`)
- правила: C2, Tor, майнінг, remote access, ризиковані протоколи, DNS bypass, VPN, torrent, lateral movement
- кореляція: portscan, sweep, P2P, спамбот

## Встановлення
1. `omada_decoders.xml` → `/var/ossec/etc/decoders/`
2. `omada_rules.xml` → `/var/ossec/etc/rules/`
3. `private-ips`, `telegram-ips`, `known-macs`, `known-aps`, `mining-pools.txt` → `/var/ossec/etc/lists/`
4. `update_ti_lists.sh` → `/usr/local/bin/`, запустити один раз вручну, потім у cron (рядок у шапці скрипта)
5. В `ossec.conf` всередині `<ruleset>` додати всі `<list>` (перелік у кінці rules-файлу)
6. `chown wazuh:wazuh /var/ossec/etc/lists/*` і `systemctl restart wazuh-manager`
7. Перевірити через `/var/ossec/bin/wazuh-logtest`

## Що перевірити в wazuh-logtest
- FTS на динамічному полі (100506)
- `negate` на `dstport` (100620)
- `<different_*>` / `<same_*>` у кореляції (Wazuh 4.3+)
- часовий пояс менеджера = Europe/Kiev (для off-hours)
