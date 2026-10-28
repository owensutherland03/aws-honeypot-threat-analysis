# IR-2026-003: Sensor Outage, Host Memory Exhaustion (OOM)

| Field | Value |
|---|---|
| **Incident ID** | IR-2026-003 |
| **Type** | Operational: availability of our own sensor (not an attacker compromise) |
| **Status** | Closed: root cause identified; sensor decommissioned 2026-10-28 |
| **Severity** | Medium: ~2 days of lost telemetry and reporting; no evidence of compromise |
| **Asset** | `honeypot-01` (EC2 `t4g.micro`, 1 GB RAM, no swap; Ubuntu 24.04 ARM64) |
| **Outage window** | Last Cowrie events 2026-10-26 · OOM kill 2026-10-27 18:26 UTC · recovered by reboot 2026-10-28 18:44 UTC |
| **Detection** | Grafana "no Cowrie events for 2h" alert (Phase 7.1), plus EC2 status check *Instance reachability: failed* |

## 1. Summary

After ~10 days of continuous bot traffic, the Cowrie process grew from ~50 MB to ~507 MB of RAM. The host has ~800 MB usable and no swap, and the container memory limit (512 MB) was too generous to protect it, so the **whole host** ran short of memory. Services starved: SSM could no longer fetch its credentials and log shipping stopped. On 2026-10-27 the daily `apt` job requested memory that didn't exist, and the kernel's **global OOM killer** terminated Cowrie. The OS stayed unresponsive (EC2 instance check failing) until a manual reboot.

## 2. Timeline (UTC)

| Time | Source | Event |
|---|---|---|
| 2026-10-15 18:24 | Cowrie log | Sensor live |
| 2026-10-17 04:00 | System log | Scheduled patch reboot (kernel `7.0.0-1014-aws`), clean boot; Cowrie restarts |
| 2026-10-17 → 10-26 | Reporter DB | Normal operation: 52–108 AbuseIPDB reports/day |
| 2026-10-21 | Event counts | **Traffic spike: 355,500 events in one day** (47 % of the whole dataset) |
| 2026-10-26 | Event counts / reporter DB | **Last day with Cowrie events and with reports** |
| 2026-10-26 22:19:39 | SSM agent (console) | `unable to acquire credentials … for ec2 identity`: SSM offline |
| 2026-10-27 18:26:15 | Kernel | `apt-get invoked oom-killer … cpuset=apt-daily.service … global_oom` |
| 2026-10-27 18:26:16 | Kernel | `Out of memory: Killed process 1234 (python3) … anon-rss:519176kB … UID:999` (Cowrie) |
| 2026-10-28 | Grafana / EC2 | No-data alert noticed; EC2 *System reachability* ✅, *Instance reachability* ❌ |
| 2026-10-28 | Analyst | Inbound 22/23 removed (stop new load), system log collected, then reboot |
| 2026-10-28 18:50 | `docker stats` | After reboot: Cowrie **52.8 MiB**, host 447 MB available |

## 3. Analysis

**Root cause: unbounded memory growth on an undersized host.** *Confidence: high.* The kernel log names the OOM event, the victim (`python3`, UID 999 = Cowrie), and its size (519,176 kB ≈ 507 MiB) directly.

**Contributing factors**

| Factor | Evidence | Why it mattered |
|---|---|---|
| Cowrie memory grew ~10× | 507 MiB at the kill vs 52.8 MiB after a fresh start | Long-running process under very high session volume (20,385 sessions; 4,700+ from one source) |
| Container limit too high for the host | `mem_limit: 512m` on a host with ~800 MB usable | The *host* exhausted memory before the *container* hit its limit. The limit should have protected the host by killing and restarting only Cowrie (`restart: unless-stopped`) |
| No swap | `Swap: 0` | No buffer for short spikes such as `apt` |
| Traffic spike | 355,500 events on 2026-10-21 | Accelerated growth. *Confidence: medium*: no memory time series was collected to tie growth to specific days |
| No memory monitoring | Only the end-to-end no-data alert existed | Memory pressure was invisible until the pipeline stopped |

**Why SSM failed first.** Under severe memory pressure the system thrashes; the SSM agent's periodic credential refresh from the instance metadata service timed out ~20 hours before the kernel finally killed Cowrie. *Confidence: medium (inferred from timing).*

**Was this an attack (denial of service)?** No evidence of compromise. Cowrie is an emulated shell and the only process named in the OOM report is Cowrie itself. The load came from ordinary bot volume rather than a targeted resource-exhaustion attempt, but heavy botnet traffic *is* the honeypot's job, so the design has to absorb it. *Confidence: medium*: a full forensic review of the host wasn't performed before decommissioning.

**Detection worked; response lagged.** The end-to-end alert designed in Phase 7.1 covered this failure (it isn't specific to any one component), but the outage lasted ~2 days before action. For a lab that's acceptable; in production the alert would page an on-call responder.

**Side finding.** The triage script `analysis/cowrie_report.py` loaded every event into memory and was itself OOM-killed while collecting the final statistics (761,650 events). It was rewritten to stream (peak ~23 MB on a 46 MB test log).

## 4. Impact

- ~2 days without telemetry (no events after 2026-10-26) and without AbuseIPDB reports.
- No admin access via SSM during the outage.
- No data loss for the period before the outage: logs on disk were intact and the final statistics were collected after the reboot.

## 5. Corrective actions (for a rebuild)

| # | Action | Status |
|---|---|---|
| 1 | Set Cowrie `mem_limit` to ~300 MB on a 1 GB host, so the container (not the host) is OOM-killed and auto-restarted | Applied to `cowrie/docker-compose.yml` |
| 2 | Add a 1 GB swap file, or use `t4g.small` (2 GB, ~$6/month more) | Documented |
| 3 | Restart Cowrie daily (e.g. systemd timer) to contain slow memory growth | Documented |
| 4 | Alert on memory, not only on missing data: CloudWatch agent `mem_used_percent` > 85 %, or Alloy's `prometheus.exporter.unix` to Grafana | Documented |
| 5 | Analysis tools must stream large logs | Done (`cowrie_report.py` rewritten) |
| 6 | Treat the no-data alert as urgent: push notification instead of email only | Documented |

## 6. Lessons

- A **resource limit is only a safeguard if it's below what the host can survive**. 512 MB "felt safe" but was more than 60 % of usable RAM.
- **End-to-end checks catch everything but explain nothing.** Pair them with resource metrics so the alert says *why*.
- **Preserve before you fix:** inbound access was closed and the system log captured *before* rebooting, which is why this report has a kernel-level timeline.
