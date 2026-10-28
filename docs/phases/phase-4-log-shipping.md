# Phase 4: Log Shipping & Dashboard

**Goal:** Every Cowrie event lands in Grafana Cloud (Loki) within seconds, searchable with LogQL and visualized on a dashboard. The honeypot can only *write* logs, never read or delete them.

**Network changes:** none inbound. Outbound HTTPS (443, already allowed) from the honeypot to Grafana Cloud. **Cost:** $0 (Grafana Cloud free tier).

## Concepts

| Concept | What it is |
|---|---|
| **Loki** | Log database. Indexes only *labels* (a few low-cardinality fields), stores the raw lines compressed. Cheap, but you must choose labels carefully. |
| **Label cardinality** | Number of distinct values a label can have. `eventid` (~30) is fine; `src_ip` (millions) would create millions of streams and break Loki. High-cardinality fields stay in the line and are parsed at query time. |
| **LogQL** | Loki's query language: `{label selectors} \| parsers \| filters`, plus metric functions like `count_over_time`. Similar in role to KQL or SPL. |
| **Grafana Alloy** | Grafana's telemetry agent (successor to Promtail / Grafana Agent). Tails files, parses, labels and pushes. |
| **Push vs pull** | The honeypot *pushes* outbound. Nothing ever connects *to* the honeypot to collect logs, so no extra inbound ports. |

---

## Part A: Grafana Cloud account and write-only token (browser)

1. Sign up at `grafana.com` with your **personal** email. Pick the free plan.
2. Create a **stack**: give it a neutral name and choose a **US East / AWS** region (closest to the honeypot).
3. **My Account (grafana.com portal) → your stack → Loki → Details** (sometimes labeled "Send Logs"). Note:
   - **URL**: `https://logs-prod-XXX.grafana.net` (the push path is `/loki/api/v1/push`)
   - **User**: a number
4. **Access Policies → Create access policy**
   - Name: `honeypot-logs-write`
   - Realm: **only this stack**
   - Scopes: **`logs: Write`**, nothing else
5. On the new policy → **Add token** → name `honeypot-01` → set an expiry (90 days, with a calendar reminder to rotate) → **copy it once**. It starts with `glc_`.

> Never paste the token into chat, a ticket, a commit or a screenshot. It goes straight into a file on the honeypot in Part C.

**Why write-only:** if the honeypot is ever compromised, the attacker finds a token that can only *add* log lines. They can't read your data, delete evidence, or touch dashboards. Scope tokens to the one action the machine needs.

---

## Part B: Give Cowrie's logs a readable home

Today the log is inside Docker's volume directory (`/var/lib/docker/...`), which only root can traverse. Running the shipper as root would work but breaks least privilege. Instead, Cowrie's log directory becomes a host bind mount at `/var/log/cowrie`, readable by **only** the `alloy` user, and **never writable** by it.

**Lesson learned the hard way (2026-10-15):** the first design gave access through the directory's *group* (`alloy`, mode 2750 + setgid). A test as the `alloy` user showed it could **write** to `cowrie.json`. Cowrie's log writer (Twisted `DailyLogFile`) explicitly `chmod 664`s its file whenever it opens or rotates it, so whoever owns the group gets write access. Default ACLs can't prevent a later `chmod`.

**Final design: named ACL entries.** On a file with an ACL, the group permission bits become the ACL *mask*, an upper bound. Cowrie's `chmod 664` can only move the mask; it can't raise the named entry `user:alloy:r--` above read.

| Object | Owner:group | Mode | ACL |
|---|---|---|---|
| `/var/log/cowrie/` | `999:root` | `2750` | `user:alloy:r-x`; default `user:alloy:r--`, `other::---` |
| `cowrie.json` | `999:root` | `664` (Cowrie forces it) | `user:alloy:r--` → effective read-only |

The directory's `other::---` blocks everyone else regardless of the file's `other` bits.

**Test artifact:** the write test that exposed the problem appended a single line `x` to `cowrie.json` at ~18:50 UTC on 2026-10-15. It was deliberately **not** removed (evidence isn't edited, even to undo a test); Alloy's JSON stage skips it.

## Part C: Install and configure Alloy

### C1. Install from Grafana's signed repo

```bash
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://apt.grafana.com/gpg.key | gpg --dearmor | sudo tee /etc/apt/keyrings/grafana.gpg >/dev/null
echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt-get update && sudo apt-get install -y alloy acl
id alloy
```

### C1b. Give Alloy its own identity and drop extra groups

The package created `alloy` with **UID 999**, the same number Cowrie uses inside its container. Linux identifies users by number and containers share the host's numbering by default, so a container escape would have landed as `alloy`. The package also adds `alloy` to `adm` and `systemd-journal` (read most of `/var/log` and the whole journal), which we don't need.

```bash
getent passwd 899 || echo "UID 899 is free"
sudo usermod -u 899 alloy                 # files in its home (/var/lib/alloy) are re-owned automatically
sudo gpasswd -d alloy adm
sudo gpasswd -d alloy systemd-journal
id alloy                                  # uid=899(alloy) gid=987(alloy) groups=987(alloy)
sudo chmod 750 /etc/alloy                 # package default 770 let alloy write its own config
```

**Residual risk:** Cowrie's *GID* 999 still equals the host's `systemd-journal` group. The full fix is Docker user-namespace remapping (Phase 7 hardening item).

### C2. Move Cowrie's logs to `/var/log/cowrie`

```bash
VOL=$(sudo docker volume inspect cowrie_cowrie-var --format '{{.Mountpoint}}')
sudo install -d -o 999 -g root -m 2750 /var/log/cowrie
sudo docker compose -f /opt/cowrie/docker-compose.yml stop
sudo cp -a "$VOL/log/cowrie/." /var/log/cowrie/
sudo chmod 2750 /var/log/cowrie            # cp -a copied the source dir's mode onto it
sudo setfacl -b /var/log/cowrie
sudo setfacl -m u:alloy:rx /var/log/cowrie
sudo setfacl -d -m u::rw,g::r,o::-,u:alloy:r /var/log/cowrie
sudo find /var/log/cowrie -type f -exec chgrp root {} + -exec setfacl -m u:alloy:r {} +
# add the bind mount line to /opt/cowrie/docker-compose.yml (see cowrie/docker-compose.yml)
sudo docker compose -f /opt/cowrie/docker-compose.yml up -d

# Prove it as the alloy user (zero-byte append test doesn't modify the file)
sudo -u alloy tail -n 1 /var/log/cowrie/cowrie.json >/dev/null && echo "alloy CAN read (good)"
sudo -u alloy sh -c 'true >> /var/log/cowrie/cowrie.json' 2>/dev/null && echo "alloy CAN WRITE (bad)" || echo "alloy cannot write (good)"
```

### C3. Store the token (never echoed, never in shell history)

```bash
read -rs -p "Paste Grafana token: " T; echo
sudo install -m 640 -o root -g alloy /dev/null /etc/alloy/loki_token
printf '%s' "$T" | sudo tee /etc/alloy/loki_token >/dev/null; unset T
sudo ls -l /etc/alloy/loki_token     # -rw-r----- root alloy
```

`read -s` hides the input. Using a variable instead of typing the token into a command keeps it out of `~/.bash_history` and out of the process list.

### C4. Deploy the config

Copy [`shipping/config.alloy`](../../shipping/config.alloy) to `/etc/alloy/config.alloy`, then fill in the two placeholders:

```bash
sudo sed -i -e 's|LOKI_PUSH_URL|https://logs-prod-XXX.grafana.net/loki/api/v1/push|' \
            -e 's|LOKI_USER_ID|123456|' /etc/alloy/config.alloy
sudo alloy fmt /etc/alloy/config.alloy >/dev/null && echo "config syntax OK"
sudo systemctl enable --now alloy && sudo systemctl restart alloy
sleep 5; systemctl is-active alloy
sudo journalctl -u alloy --since "2 min ago" --no-pager | grep -iE "error|warn" | tail -20
sudo ss -tlnp | grep alloy        # UI must be on 127.0.0.1:12345 only
```

---

## Part D: First LogQL queries (Grafana → Explore → Loki data source)

```logql
# Everything from the honeypot
{job="cowrie"}

# Only login attempts, parsed
{job="cowrie", eventid=~"cowrie.login.(success|failed)"} | json | line_format "{{.src_ip}}  {{.username}} / {{.password}}"

# Commands typed by attackers
{job="cowrie", eventid="cowrie.command.input"} | json | line_format "{{.src_ip}}  {{.input}}"

# Events per minute by type
sum by (eventid) (count_over_time({job="cowrie"}[1m]))

# Top 10 source IPs in the last 24h
topk(10, sum by (src_ip) (count_over_time({job="cowrie", eventid="cowrie.session.connect"} | json [24h])))
```

---

## Part E: Dashboard

[`dashboards/cowrie-overview.json`](../../dashboards/cowrie-overview.json) is an importable Grafana dashboard (17 panels, timezone **UTC**).

**Import:** Grafana → **Dashboards → New → Import** → upload the JSON → when prompted for *Loki (honeypot logs)*, pick `grafanacloud-<stack>-logs` → **Import**.

| Row | Panels | Query technique |
|---|---|---|
| Stats | Sessions, unique IPs, failed/successful logins, commands, downloads | `sum(count_over_time(...[$__range]))` as an *instant* query = total over the dashboard's time range |
| Trends | Connections by protocol; events by type | `sum by (label) (count_over_time(...[$__interval]))` as a *range* query = one bar per time bucket |
| Top-N tables | Source IPs, usernames, passwords, credential pairs, commands, SSH client versions, HASSH | `topk(15, sum by (field) (count_over_time({...} \| json [$__range])))`, Loki returns one table (label columns + `Value #A`); an *Organize* transform hides `Time` and renames columns, then *Sort by* Count. (A first version used *Reduce: series to rows*, which collapsed the table to its last row.) |
| Live feeds | Recent commands; downloads with SHA-256 | Log queries with `line_format` |

**Why "unique IPs" matters:** a single bot reconnecting every 13 seconds produces thousands of sessions. Session counts measure *noise*; distinct IPs measure *breadth*.

**Not included yet:** country/ASN enrichment. Cowrie's JSON has no geolocation; adding it means a GeoIP database (e.g. MaxMind GeoLite2) in the Alloy pipeline, a Phase 7 candidate.

---

## Verification checklist

- [x] Token is scoped to `logs:write` on this stack only, IP-restricted to the Elastic IP, 90-day expiry (wizard token exposed in chat was revoked)
- [ ] `/etc/alloy/loki_token` is `root:alloy 0640`; token never in chat, history or repo
- [x] `alloy` has its own UID (899), no `adm`/`systemd-journal`; `/etc/alloy` is 750
- [x] `/var/log/cowrie` is `999:root 2750` with `user:alloy:r--` ACL; tested: alloy can read, cannot write
- [x] Alloy active, no errors; UI bound to `127.0.0.1` only; metrics show read = sent (230), HTTP 204, 0 dropped
- [x] `{job="cowrie"}` returns events in Grafana Explore, with correct (event-time) timestamps
- [x] Dashboard imported and rendering (stats, trends, Top-N tables, live feeds); JSON in `dashboards/`

## First observations from the dashboard (2026-10-15, first ~40 minutes live)

- **42 sessions from 8 IPs**, mostly Telnet (34 vs 8 SSH). One IP produced 25 sessions alone, which is why "unique IPs" sits next to "sessions".
- **Router CLI escape sequence:** `enable` → `system` → `shell` → `sh` → `ping; sh`, each seen 6×. Bots built for routers whose vendor CLI hides the Linux shell try every known "escape" command; `ping; sh` abuses command injection in a restricted CLI.
- **Write+execute probing:** `>/dir/.f && chmod 777 /dir/.f && /dir/.f` across `/etc`, `/mnt`, `/usr`, `/boot`, `/home`, `/root`, finding a directory where the payload can be dropped and run.
- **`admin/admin`** is the top credential pair (default credentials, T1078.001).
- **`SSH-2.0-ZGrab ZGrab SSH Survey`** is an internet-survey scanner, a reporter-allowlist candidate (Phase 6).
- Dashboard still includes our own test traffic (`172.18.0.1`, the CloudShell IP); the Phase 6 allowlist covers these.
