# AWS Honeypot & Threat Analysis Lab

An SSH/Telnet honeypot built with **Cowrie** on **Ubuntu Server 24.04 (ARM64) in AWS**, logs centralized in **Grafana Cloud (Loki)**, attacker activity mapped to **MITRE ATT&CK**, and confirmed attackers reported to **AbuseIPDB**.

Every component was built and configured individually (no all-in-one stack) to capture real attacker behavior and turn it into incident-style analysis.

> **Status:** Lab concluded (October 2026). Ran live on the internet for ~2 weeks; the infrastructure is being decommissioned. A final **Results** section follows the shutdown.

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
| 7 | Extras (web honeypot) & public-release hardening | ⬜ |

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
