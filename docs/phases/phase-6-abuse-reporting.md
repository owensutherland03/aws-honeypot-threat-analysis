# Phase 6: Reporting Attackers to AbuseIPDB

**Goal:** Automatically share attacker IPs with the community, carefully: only real login/command activity, never our own or research IPs, no duplicates, within free-tier limits, with the API key kept away from the internet-facing process.

**Network changes:** none inbound. Outbound HTTPS to `api.abuseipdb.com` (already allowed). **Cost:** $0.

## Why our own script instead of Cowrie's `output_abuseipdb` plugin

| Requirement | Cowrie plugin | [`reporter/abuse_reporter.py`](../../reporter/abuse_reporter.py) |
|---|---|---|
| Where the API key lives | Inside the Cowrie container (the attacker-facing process) | Separate sandboxed systemd service on the host |
| Allowlist | No | CIDR allowlist + forward-confirmed reverse DNS for research scanners + scanner SSH banners |
| Only logins/commands | Login-based | Login attempts **or** commands; pure scans never reported |
| Dry run with sample output | No | Default mode |
| Cooldown / caps | Re-report window | Per-IP cooldown, per-run and per-day caps, 15-min AbuseIPDB rule handled |

## Reporting rules

| Rule | Implementation |
|---|---|
| Eligible | ≥1 `login.success`/`login.failed` **or** ≥1 `command.input` in the lookback window |
| Never reported | Private/reserved IPs (e.g. `172.18.0.1`), the sensor's own IP, allowlist entries, research scanners |
| Research scanners | SSH banner contains zgrab/censys/shodan/nmap/masscan, **or** reverse DNS ends in a known scanner domain *and* resolves back to the same IP (FCrDNS, so a fake PTR can't evade reporting) |
| Cooldown | 24 h per IP (`COOLDOWN_HOURS`) |
| Caps | 50 per run, 900 per day (free tier allows 1,000) |
| Categories | Always **18** Brute-Force; **22** SSH or **23** IoT Targeted (Telnet); **15** Hacking if commands were run |
| Comment | Protocol, attempt count, up to 3 usernames, command count, UTC window. **No passwords, no sensor IP, no personal data** (comments are public). |
| Fail-safe | Anything other than `REPORTER_DRY_RUN=false` is a dry run; live mode refuses to start without a key |

Example comment:
> Honeypot: TELNET login attempts (2 attempts, users: admin) followed by 26 shell commands between 2026-10-15T19:12Z and 2026-10-15T19:12Z.

## Part A: AbuseIPDB account and API key (browser)

1. Register at `abuseipdb.com` with your **personal** email and verify it.
2. **Account → API** → **Create Key** → name `honeypot-01-reporter-2026-10` → copy it into your password manager. Don't paste it into chat.
3. Check the free-tier limits shown on the API page (reports/day) and adjust `MAX_PER_DAY` if needed.

## Part B: Install the reporter (honeypot host)

1. **Dedicated user with an explicit UID.** `useradd -r` would pick the highest free system UID, which is now 999, the UID Cowrie uses inside its container. The same collision we fixed for Alloy.
2. **Read-only log access** via a named ACL entry (same design as Alloy).
3. Script in `/opt/honeypot-reporter/`, config in `/etc/honeypot-reporter/` (`reporter.env` root:hpreporter 0640, `allowlist.txt`).
4. API key written with `read -s` (never echoed, never in shell history).
5. systemd service with sandboxing (`ProtectSystem=strict`, no capabilities, `NoNewPrivileges`, only INET/UNIX sockets) and a 15-minute timer, installed but **not enabled** until the dry run is reviewed.

## Part C: Dry run and review

```bash
sudo systemctl start honeypot-reporter.service     # REPORTER_DRY_RUN=true
sudo journalctl -u honeypot-reporter --since "5 min ago" --no-pager
# or, for a wider first look (systemd loads the env file, so the key never
# appears on a command line or in the process list):
sudo systemd-run --wait --pipe --quiet --uid=hpreporter --gid=hpreporter \
     -p EnvironmentFile=/etc/honeypot-reporter/reporter.env \
     /usr/bin/python3 -I /opt/honeypot-reporter/abuse_reporter.py --lookback 24
```

Never pass secrets as command-line arguments (`env KEY=... cmd`, `curl -H "Key: ..."`): any local user can read them from `ps`/`/proc/<pid>/cmdline`.

Review every `WOULD` line (IP, categories, comment) and every `SKIP` reason before going live.

## Part D: Go live

Set `REPORTER_DRY_RUN=false`, run once manually and verify `SENT` lines and the reports on your AbuseIPDB dashboard, then `systemctl enable --now honeypot-reporter.timer`.

## Optional: SANS DShield

Cowrie has a built-in `output_dshield` plugin, but it would put the DShield key inside the internet-facing container, the same concern as above. Alternative: run the official DShield sensor separately, or extend this reporter. Deferred.

## Privacy note

Reverse-DNS lookups of attacker IPs go to DNS servers that the attacker's network may control, so they can see that "someone" looked them up. That's acceptable here (it only reveals AWS's resolver), and it's why the check is a lookup and not a connection to the attacker.

## Go-live record (2026-10-15)

| Check | Result |
|---|---|
| Dry run (3 h lookback) | 2 `WOULD` (the IR-2026-001 botnet hosts), 8 `SKIP` (6 scan-only incl. the ZGrab survey, CloudShell allowlisted, Docker bridge private). Samples reviewed and approved. |
| API key stored | `read -s` → pipe → `tee`; file `root:hpreporter 0640`; verified by length (80), never displayed |
| First live run | 3 `SENT`: the two approved hosts (AbuseIPDB confidence 100) plus `79.106.125[.]108` (confidence 64), which arrived between the dry run and go-live |
| Post-hoc check of the unreviewed report | `79.106.125[.]108`: Telnet `login.success` (`root` / a wordlist password), no commands. Eligible under the approved rules. Its TTY hash `e3b0c442…b855` is the SHA-256 of **empty input**: it logged in and typed nothing. |
| Second live run | All 3 skipped by the 24 h cooldown, `0 eligible` |
| Timer | Enabled, every 15 min. First automatic run 20:00:21 UTC: `LIVE`, 4 IPs in the 1 h window, 2 scan-only + 2 cooldown skips, exited cleanly |
| Finding | `state.db` was created `0644` in a `0755` directory: the manual `systemd-run` didn't carry the service's `UMask=0077`, and `StateDirectory=` defaults to `0755`. Fixed with `chmod` and `StateDirectoryMode=0700` in the unit (systemd re-applies it on every start). Verified `drwx------` / `-rw-------`. |

**Lesson:** approval was given to the *rules*, not to every individual report. Automation acts on what arrives after the review, which is why the rules were tested against edge cases first and why the first unreviewed report was checked afterwards.
