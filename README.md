# AWS Honeypot & Threat Analysis Lab

An SSH/Telnet honeypot built with **Cowrie** on **Ubuntu Server 24.04 (ARM64) in AWS**, logs centralized in **Grafana Cloud (Loki)**, attacker activity mapped to **MITRE ATT&CK**, and confirmed attackers reported to **AbuseIPDB**.

Every component was built and configured individually (no all-in-one stack) to capture real attacker behavior and turn it into incident-style analysis.

> **Status:** Decommissioned 2026-10-28 after 12 days of live data (2026-10-15 → 10-26). Infrastructure torn down; code, configs, detections and incident reports remain here.

## What it does

A home lab for studying attacker behavior end to end:

**collect → centralize → detect/visualize → analyze → map to ATT&CK → report → respond (abuse reporting)**

## Architecture (summary)

```
Internet ──22/23──► AWS EC2 (isolated VPC)
                    ├─ Cowrie honeypot (container, unprivileged)
                    ├─ Grafana Alloy ──HTTPS──► Grafana Cloud (Loki + dashboards)
                    └─ Abuse reporter ─HTTPS──► AbuseIPDB / DShield
Admin access: AWS SSM Session Manager (no admin SSH port exposed)
Home network: never connected. Browser-only access to AWS console & Grafana.
```

Full design, trust boundaries, cost, and risk register: **[docs/architecture.md](docs/architecture.md)**

| Layer | Choice | Why |
|---|---|---|
| Hosting | AWS EC2 `t4g.micro`, dedicated VPC | Physical separation from home LAN, cloud-security skills |
| Honeypot | [Cowrie](https://github.com/cowrie/cowrie) | Medium-interaction SSH/Telnet; logs creds, commands, downloads as JSON |
| Admin access | AWS SSM Session Manager | No inbound management port, IAM-authenticated, audited |
| Log shipping | Grafana Alloy | Outbound-only push, lightweight |
| SIEM / dashboard | Grafana Cloud free tier (Loki + Grafana) | $0, LogQL queries, good dashboards |
| Threat intel out | AbuseIPDB (+ optional DShield) | Contribute back; dedupe, allowlist, dry-run first |

**Estimated cost:** ~$12/month (EC2 + public IPv4 + disk). Everything else is free tier.

## Results (2026-10-15 → 2026-10-26)

The sensor collected data for 12 days, then failed from host memory exhaustion ([IR-2026-003](incidents/IR-2026-003-sensor-outage-memory-exhaustion.md)) and was decommissioned on 2026-10-28.

| Metric | Value |
|---|---|
| Events | **761,650** |
| Sessions | **20,385** (13,670 Telnet · 6,715 SSH) |
| Unique source IPs | **1,534** |
| Logins accepted / rejected | 16,729 / 377 (the userdb accepts almost everything by design) |
| Commands captured | **407,959** |
| Files captured | **29 payloads**: 20 ARM bot builds, 5 x86-64 binaries, 4 downloader scripts ([IR-2026-004](incidents/IR-2026-004-multi-arch-botnet-payloads.md)) |
| Download attempts blocked / failed | 811 (egress allowed only TCP 80/443) |
| IPs reported to AbuseIPDB | **751** (860 reports, 36–108 per day) |
| Time to first attacker | < 1 minute after the ports opened |
| Busiest day | 2026-10-21: 355,500 events (47 % of the dataset) |

**Top credentials:** `admin/admin` (2,114) · `root/vizxv` · `root/admin` · `root/xc3511` · `support/support` · `root/888888` · `root/juantech`. Nearly all come from the default-credential list in the public Mirai source code.

**What attackers did:** almost all traffic was automated IoT botnet activity: router-CLI escapes (`enable` → `system` → `shell` → `sh`), BusyBox checks, writable-directory probing, multi-protocol malware downloads, and a competitor-killer script run 4,000+ times that hunts rival bots by their deleted executables.

**Campaigns** were separated by Cowrie's session-recording hash: identical recordings from different IPs mean the same script.

| Report | What it covers |
|---|---|
| [IR-2026-001](incidents/IR-2026-001-telnet-botnet-loader.md) | Telnet loader campaign on a 15-minute cadence; identical session hashes across sources |
| [IR-2026-002](incidents/IR-2026-002-multi-protocol-dropper.md) | wget → tftp → ftpget dropper; two of three delivery paths **blocked by egress rules** |
| [IR-2026-003](incidents/IR-2026-003-sensor-outage-memory-exhaustion.md) | Our own outage: Cowrie grew ~10×, host OOM; root cause and fixes |
| [IR-2026-004](incidents/IR-2026-004-multi-arch-botnet-payloads.md) | `jkl*` kit: 11-architecture downloader with `selfrep` self-propagation; 29 files hashed |

**ATT&CK coverage:** 13 techniques observed across 7 tactics. See [`detections/attack-mapping.md`](detections/attack-mapping.md), each with a LogQL query.

**Lessons**
- **Egress filtering works.** It blocked TFTP/FTP malware delivery, but allowing a whole port (80) still let one kit through. Allow destinations, not ports.
- **Size resource limits for the host, not the process.** A 512 MB container limit on a 1 GB host let the host run out of memory first.
- **End-to-end "no data" alerts catch every failure**, but need resource metrics alongside them to explain *why*.
- **Analysis tooling has to stream** at honeypot scale (the first report script was itself OOM-killed at 761k events).

## Project phases

| # | Phase | Status |
|---|---|---|
| 0 | Repo foundation, secret-scanning guardrails, architecture | ✅ |
| 1 | AWS account hardening (MFA, admin identity, budget alarm) | ✅ |
| 2 | Network & compute (VPC, security group, EC2, SSM) | ✅ |
| 3 | Cowrie install & verification | ✅ |
| 4 | Log shipping & Grafana dashboard | ✅ |
| 5 | MITRE ATT&CK mapping & incident summaries | ✅ (ongoing: new incidents as data arrives) |
| 6 | AbuseIPDB reporting (dry run → enable; DShield deferred) | ✅ |
| 7 | Extras & public release (no-data alert, outage RCA, publication) | ✅ partial |

Build notes for each phase (what was built and why) are in [`docs/phases/`](docs/phases/).

## Repository layout

```
.
├── docs/
│   ├── architecture.md      # design, data flow, trust boundaries, risks
│   └── phases/              # step-by-step build notes per phase
├── infra/                   # (Phase 2) AWS setup scripts / IaC
├── cowrie/                  # (Phase 3) Cowrie config overrides & compose file
├── shipping/                # (Phase 4) Grafana Alloy config
├── dashboards/              # (Phase 4) exported Grafana dashboard JSON
├── analysis/                # (Phase 5) cowrie_report.py: triage summary & session timelines
├── detections/              # (Phase 5) ATT&CK mapping rules & LogQL queries
├── incidents/               # (Phase 5) incident write-ups
├── reporter/                # (Phase 6) AbuseIPDB / DShield reporter
├── .env.example             # template for secrets (real .env is gitignored)
└── .pre-commit-config.yaml  # local secret scanning (gitleaks)
```

## Safety principles

1. **No path to the home network.** No VPN, tunnel, agent, or shared credential links the lab to my LAN.
2. **No secrets in git.** Real values live only in a `chmod 600` `.env` on the host. Gitleaks scans every commit locally and in CI.
3. **Least privilege everywhere:** a minimal IAM role, an unprivileged honeypot user, egress limited to 80/443, and a write-only log token.
4. **Disposable infrastructure.** If the host is ever in doubt, terminate it and rebuild from this repo.
5. **No malware in the repo.** Only hashes and links to public analysis.
6. **Redaction before publishing.** My own IPs, AWS account IDs, and tokens are scrubbed (see Phase 7 checklist).

## Disclaimer

This project is for defensive research and education. The honeypot only emulates services and does not attack or retaliate. Reported IPs are limited to hosts that actively attempted authentication or command execution against the honeypot.
