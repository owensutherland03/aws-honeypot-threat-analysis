# MITRE ATT&CK Mapping for Cowrie Events

How behaviour seen by the honeypot maps to [MITRE ATT&CK Enterprise](https://attack.mitre.org/) techniques, with a LogQL query to find each one in Grafana (data source: `grafanacloud-<stack>-logs`).

**Status** reflects the data collected so far (updated 2026-10-16, ~19.5 h live). Re-check with [`analysis/cowrie_report.py`](../analysis/cowrie_report.py).

**Visibility caveat:** Cowrie is medium-interaction. It records what attackers *type and attempt*; nothing actually executes. A mapping means "the attacker attempted this technique", not "the technique succeeded".

## Attack flow seen on a typical IoT botnet session

```
Reconnaissance    Initial Access         Execution            Discovery                    Defense Evasion         C2 / Impact
T1595.001   →     T1133 + T1078.001  →   T1059.004       →    T1082, T1083            →    T1222.002, T1564.001 →  T1105 → T1496
scan 22/23        Telnet admin/admin     shell / ping; sh     busybox, /proc/self/exe      chmod 777, ".f" files   (download, mine)
```

## Mapping table

| Tactic | Technique | Cowrie evidence | Status |
|---|---|---|---|
| Reconnaissance | **T1595.001** Active Scanning: Scanning IP Blocks | `session.connect` with no login attempt; research scanners (`SSH-2.0-ZGrab ZGrab SSH Survey`) | ✅ Observed (25 sessions from one Telnet scanner; 1 ZGrab survey) |
| Initial Access | **T1133** External Remote Services | Any login over exposed SSH/Telnet | ✅ Observed |
| Initial Access / Persistence | **T1078.001** Valid Accounts: Default Accounts | `login.success` with vendor defaults (`admin/admin`, `root/root`, `ubnt/ubnt`...) | ✅ Observed (10× `admin/admin`) |
| Credential Access | **T1110.001** Brute Force: Password Guessing | Bursts of `login.failed` from one IP | ✅ Observed: Campaign C cycles the Mirai credential list one pair per session (~1,100 sessions); few `login.failed` because the userdb accepts almost everything |
| Credential Access | **T1110.003** Brute Force: Password Spraying | One password tried across many usernames | ⏳ Not yet |
| Execution | **T1059.004** Command and Scripting Interpreter: Unix Shell | `command.input`; router-CLI escapes `sh`, `shell`, `system`, `ping; sh` | ✅ Observed |
| Discovery | **T1082** System Information Discovery | `uname`, `/proc/cpuinfo`, `nproc`, `/bin/busybox <WORD>`, `cat /proc/self/exe` (ELF header → CPU arch) | ✅ Observed |
| Discovery | **T1083** File and Directory Discovery | Probing many directories for a writable + executable location | ✅ Observed (`>/dir/.f && chmod 777 /dir/.f && /dir/.f` over 13 dirs) |
| Discovery | **T1033** System Owner/User Discovery | `whoami`, `id`, `w`, `last` | ⏳ Not yet |
| Defense Evasion | **T1222.002** File and Directory Permissions Modification: Linux | `chmod 777`, `chmod +x` | ✅ Observed |
| Defense Evasion | **T1564.001** Hide Artifacts: Hidden Files and Directories | Dot-files/dirs (`/var/.f`, `/tmp/.x`, `/dev/shm/.`) | ✅ Observed |
| Defense Evasion | **T1070.003** Indicator Removal: Clear Command History | `history -c`, `unset HISTFILE`, deleting `.bash_history` | ⏳ Not yet |
| Defense Evasion | **T1027** Obfuscated Files or Information | `base64 -d`, `echo -e '\x..'` payloads | ✅ Observed (`echo -e "\x47\x41…"` = `GAYFGT`, Gafgyt marker) |
| Command and Control | **T1105** Ingress Tool Transfer | `wget`/`curl`/`tftp`/`ftpget`; `session.file_download` with SHA-256 | ✅ Attempted (IR-2026-002: wget/tftp/ftpget, all failed) |
| Defense Evasion | **T1070.004** Indicator Removal: File Deletion | `rm -rf` of a file right after running it | ✅ Observed (IR-2026-002) |
| Discovery | **T1057** Process Discovery | Looping over `/proc/*`, `ps` | ✅ Observed (Campaign D competitor-killer) |
| Persistence | **T1098.004** Account Manipulation: SSH Authorized Keys | Writing to `~/.ssh/authorized_keys` | ⏳ Not yet |
| Persistence | **T1053.003** Scheduled Task/Job: Cron | `crontab`, writes to `/etc/cron*` | ⏳ Not yet |
| Impact | **T1531** Account Access Removal | `passwd` / `chpasswd` to lock out the real owner | ⏳ Not yet |
| Impact | **T1496** Resource Hijacking (compute hijacking) | `xmrig`, `stratum+tcp://`, mining pool hostnames | ⏳ Not yet |

## LogQL detections

Run in Grafana **Explore** (Code mode). Most use a 24h window; adjust as needed.

### T1595.001: Scanning (connections that never try to log in)
```logql
sum by (src_ip) (count_over_time({job="cowrie", eventid="cowrie.session.connect"} | json [24h]))
  unless
sum by (src_ip) (count_over_time({job="cowrie", eventid=~"cowrie.login.*"} | json [24h]))
```

### T1078.001: Logins with default credentials
```logql
{job="cowrie", eventid="cowrie.login.success"} | json
  | username=~"admin|root|ubnt|support|user|guest|default|pi|test"
  | password=~"admin|root|ubnt|support|user|guest|default|raspberry|1234|12345|123456|password|"
  | line_format "{{.src_ip}}  {{.protocol}}  {{.username}}/{{.password}}"
```

### T1110.001: Password guessing (≥ 10 failures per IP per 10 min)
```logql
sum by (src_ip) (count_over_time({job="cowrie", eventid="cowrie.login.failed"} | json [10m])) >= 10
```

### T1059.004: Router CLI escape attempts
```logql
{job="cowrie", eventid="cowrie.command.input"} | json
  | input=~"^(sh|shell|system|enable|linuxshell)$|.*ping; sh.*"
```

### T1082: System information discovery
```logql
{job="cowrie", eventid="cowrie.command.input"} | json
  | input=~".*(uname|/proc/cpuinfo|nproc|lscpu|/proc/self/exe|busybox [A-Z]{4,}).*"
```

### T1083 + T1222.002 + T1564.001: Writable-directory probing with hidden files
```logql
{job="cowrie", eventid="cowrie.command.input"} | json
  | input=~".*>/[^ ]*/\\.[^ /]+ && chmod 777.*"
```

### T1105: Ingress tool transfer
```logql
{job="cowrie", eventid=~"cowrie.command.input|cowrie.session.file_download"} | json
  | input=~".*(wget|curl|tftp|ftpget).*" or url!=""
  | line_format "{{.src_ip}}  {{.input}}{{.url}}  {{.shasum}}"
```

### T1098.004: SSH key persistence
```logql
{job="cowrie", eventid="cowrie.command.input"} | json | input=~".*authorized_keys.*"
```

### T1053.003: Cron persistence
```logql
{job="cowrie", eventid="cowrie.command.input"} | json | input=~".*(crontab|/etc/cron).*"
```

### T1070.003: Clear command history
```logql
{job="cowrie", eventid="cowrie.command.input"} | json | input=~".*(history -c|unset HISTFILE|bash_history).*"
```

### T1496: Cryptomining
```logql
{job="cowrie", eventid="cowrie.command.input"} | json
  | input=~"(?i).*(xmrig|stratum\\+tcp|minerd|c3pool|nanopool|moneroocean).*"
```

### Campaign detection: same command script from multiple IPs
```logql
count by (input) (
  sum by (input, src_ip) (count_over_time({job="cowrie", eventid="cowrie.command.input"} | json | input!="" [24h]))
) >= 2
```
Commands typed identically by two or more different IPs usually mean one botnet running one script.
