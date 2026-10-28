# IR-2026-001: Telnet IoT Botnet Loader Campaign (15-minute cadence)

| Field | Value |
|---|---|
| **Incident ID** | IR-2026-001 |
| **Status** | Closed: monitored, no impact |
| **Severity** | Low on the honeypot (emulated system, nothing executed). Would be **High** on a real IoT device with default credentials. |
| **Sensor** | `honeypot-01` (Cowrie, Telnet/23, persona `prod-db-02`) |
| **First seen** | 2026-10-15 18:34:32 UTC |
| **Last seen** | Ongoing (see update below) |
| **Sources** | `128.201.187[.]183` (4 runs), `183.128.163[.]123` (1 run) |
| **Detection** | Dashboard "Top commands" + `cowrie_report.py` session ranking |

## 1. Summary

Two internet hosts logged in to the honeypot over **Telnet** with the default credential **`admin/admin`** and executed an identical, fully automated two-stage script typical of **Mirai-family IoT botnets**:

1. **Stage 1, fingerprinting:** escape a router CLI into a Linux shell, confirm BusyBox, and read `/proc/self/exe` to identify the CPU architecture.
2. **Stage 2, staging:** probe 13 directories for one that is both writable and executable, using a hidden file `.f`.

Both hosts produced **byte-identical session recordings** (same TTY SHA-256), proving they run the same tooling. One host repeated the attack **every ~15 minutes** like a scheduled job. No malware was downloaded: the script stopped after stage 2, most likely because Cowrie's emulated answers didn't satisfy its architecture check.

## 2. Timeline (UTC)

**Run observed from `183.128.163[.]123`**, identical to every run from `128.201.187[.]183`:

| Time | Session | Event |
|---|---|---|
| 18:34:32.016 | `5bb8f6e08e38` | Telnet connection (src port 40898) |
| 18:34:33.467 | `5bb8f6e08e38` | **Login success `admin/admin`** |
| 18:34:33.766–.785 | `5bb8f6e08e38` | `sh`, `shell`, `enable`, `system`, `ping; sh`: router CLI escape sequence, **3 ms apart** |
| 18:34:34.125 | `5bb8f6e08e38` | `/bin/busybox HISILICON`: BusyBox presence check |
| 18:34:34.763 | `5bb8f6e08e38` | `/bin/busybox cat /proc/self/exe \|\| cat /proc/self/exe`: read own binary (ELF header → CPU arch) |
| 18:34:35.093 | `5bb8f6e08e38` | Session closed after 3.1 s |
| 18:34:35.325 | `b3752b671122` | **Reconnects 0.2 s later**, logs in again with `admin/admin` |
| 18:34:36.806–37.103 | `b3752b671122` | Same escape sequence + `busybox HISILICON` |
| 18:34:37.569–37.916 | `b3752b671122` | `>/DIR/.f && chmod 777 /DIR/.f && /DIR/.f && cd /DIR/;` for `/var`, `/var/tmp`, `/var/run`, `/dev`, `/dev/shm`, `/data`, `/etc`, `/mnt`, `/usr`, `/boot`, `/home`, `/root`: one directory every ~15 ms |
| 18:34:38.184 | `b3752b671122` | Session closed after 2.9 s; no further activity from this IP |

**Recurrence from `128.201.187[.]183`** (each run = stage-1 session + stage-2 session):

| Run | Stage 1 | Stage 2 | Gap |
|---|---|---|---|
| 1 | 18:42:30 | 18:42:31 | n/a |
| 2 | 18:57:27 | 18:57:29 | 14 m 57 s |
| 3 | 19:12:14 | 19:12:17 | 14 m 47 s |
| 4 | 19:27:18 | 19:27:19 | 15 m 04 s |

## 3. Analysis

**Fully automated.** Commands arrive 3–17 ms apart, each full session lasts 1.3–3.1 s, and the reconnect between stages takes ~0.2 s. No human types this way.

**Same campaign, two infected hosts.** Evidence, strongest first:
1. Identical TTY recording hashes across both IPs (`52e9b844…` for stage 1, `d4c6234f…` for stage 2). Cowrie hashes each session's terminal recording (and marks repeats as `"duplicate": true`), so identical hashes mean the recorded terminal content was exactly the same.
2. Identical command sequence, including the distinctive marker string `HISILICON` and the same 13-directory order.
3. Same credential and same two-session structure.

**Why two sessions.** Stage 1 reports the target's architecture back to the botnet's loader; stage 2 finds where a binary can be written and executed. A real infection would continue with a third step: transferring a binary built for that architecture (via `wget`/`tftp`, or byte-by-byte with `echo -ne '\x..'`), then running it.

**Why no payload arrived.** `cat /proc/self/exe` on a real device returns an ELF binary whose header encodes the CPU type. Cowrie returns emulated output instead, so the loader most likely couldn't select a matching payload and moved on. *Confidence: medium.* This is consistent with the absence of any download attempts, but the loader's server-side logic isn't visible to us.

**Marker string `HISILICON`.** Running BusyBox with a nonexistent applet name returns `HISILICON: applet not found`. The bot uses the echoed string to confirm it's on a real BusyBox shell and to delimit output. HiSilicon is a chipset vendor common in IP cameras and DVRs, suggesting the botnet targets that device class. The original Mirai used `ECCHI` the same way.

**The sources are likely victims too.** Both IPs connect from end-user address space rather than hosting providers, consistent with already-infected IoT devices scanning for new victims. *Confidence: medium*; confirm with an IP reputation/ASN lookup before acting on it.

**The 15-minute cadence** suggests a fixed retry timer in the bot. A target that "accepted" the login gets re-attacked on schedule, which also means blocking by IP has limited value: the botnet has many interchangeable nodes.

## 4. Indicators

| Type | Indicator | Notes |
|---|---|---|
| IPv4 | `128.201.187[.]183` | 4 runs, ongoing |
| IPv4 | `183.128.163[.]123` | 1 run |
| Credential | `admin` / `admin` | Default IoT credential |
| Command string | `/bin/busybox HISILICON` | Campaign marker |
| Command pattern | `>/<dir>/.f && chmod 777 /<dir>/.f && /<dir>/.f && cd /<dir>/;` | Writable+executable dir probe |
| Command | `/bin/busybox cat /proc/self/exe \|\| cat /proc/self/exe` | Architecture fingerprinting |
| Command sequence | `sh` → `shell` → `enable` → `system` → `ping; sh` | Router CLI escape |
| Session hash (internal) | `52e9b844cab6d6b643be95b12df186d807af346df86502511b741a6e3c679d57` | Cowrie TTY log, stage 1. Not a malware hash. |
| Session hash (internal) | `d4c6234f92f0927070bd79f204505347896699a0825457681216dd4de5b90315` | Cowrie TTY log, stage 2. Not a malware hash. |

## 5. MITRE ATT&CK

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1133 External Remote Services | Login via exposed Telnet |
| Initial Access | T1078.001 Valid Accounts: Default Accounts | `admin/admin` |
| Execution | T1059.004 Unix Shell | `sh`, `shell`, `system`, `ping; sh` |
| Discovery | T1082 System Information Discovery | `busybox HISILICON`, `cat /proc/self/exe` |
| Discovery | T1083 File and Directory Discovery | 13-directory writable/executable probe |
| Defense Evasion | T1222.002 Linux File Permissions Modification | `chmod 777 /<dir>/.f` |
| Defense Evasion | T1564.001 Hidden Files and Directories | `.f` dot-file |
| *(not reached)* | T1105 Ingress Tool Transfer | Expected next step; not observed |

## 6. Recommended actions

*Written as they would apply to a real network where this traffic hit a production device.*

1. **Disable Telnet** on all devices; it should never be internet-facing. Restrict management interfaces to a management VLAN/VPN.
2. **Eliminate default credentials** (`admin/admin` and similar) across IoT/OT inventory; enforce unique passwords at deployment.
3. **Hunt** for the stage-2 pattern on managed Linux/IoT hosts: hidden files named `.f` in `/var`, `/tmp`, `/dev/shm`, `/data`, and BusyBox invoked with uppercase nonsense arguments.
4. **Block at the edge** as a short-term measure only. Botnet nodes rotate, so IP blocks decay quickly; behavioural detections (above) last longer.
5. **Report** both IPs to AbuseIPDB (categories: Brute-Force, IoT Targeted, Telnet), handled by the Phase 6 reporter.
6. **Honeypot improvement:** emulate a plausible ELF header for `/proc/self/exe` so loaders proceed to the download stage and payloads can be captured and hashed (Phase 7 candidate).

## 7. Detection queries (Grafana / LogQL)

```logql
# Campaign marker
{job="cowrie", eventid="cowrie.command.input"} | json | input=~".*busybox HISILICON.*"

# Stage-2 directory probe
{job="cowrie", eventid="cowrie.command.input"} | json | input=~".*>/[^ ]*/\\.f && chmod 777.*"

# Re-attack cadence per source (sessions per 15 min)
sum by (src_ip) (count_over_time({job="cowrie", eventid="cowrie.login.success"} | json | username="admin", password="admin" [15m]))
```

## Update: 2026-10-16

By 2026-10-16 13:57 UTC, `128.201.187[.]183` had completed **42 runs** (84 sessions) with byte-identical recordings (`52e9b844…` / `d4c6234f…`), still on its ~15-minute cadence for over 19 hours. No new sources ran this script; no payload was ever delivered. The campaign is a persistent, single-script retry loop. Related but distinct activity seen in the same window (a multi-protocol dropper, a credential sweeper and a competitor-killer script) is tracked separately; see [`notes/2026-10-16-triage.md`](notes/2026-10-16-triage.md) and IR-2026-002.
