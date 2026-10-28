# Architecture

## 1. Goals and constraints

| Goal | Constraint that shapes the design |
|---|---|
| Capture real SSH/Telnet attacker behavior | Must be internet-facing on ports 22/23 |
| Zero risk to home network | Honeypot hosted in the cloud; no connectivity to the LAN at all |
| Central logging + dashboard | Budget about $15/month, so a free-tier SaaS SIEM instead of self-hosted Elastic |
| Reproducible | Everything rebuildable from this repo; no secrets in git |

## 2. Diagram

```
                      INTERNET (attackers / scanners)
                                  │
                       TCP 22 (SSH), 23 (Telnet)
                                  ▼
┌──────────────────── AWS account ─────────────────────────────────┐
│  VPC "honeypot-vpc" (dedicated; nothing else lives here)         │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ Security Group "honeypot-sg"                               │  │
│  │   IN : 22, 23 from 0.0.0.0/0   ← the ONLY open ports       │  │
│  │   OUT: 80, 443 only                                        │  │
│  │  ┌──────────────────────────────────────────────────────┐  │  │
│  │  │ EC2 t4g.micro · Ubuntu 24.04 LTS (ARM)               │  │  │
│  │  │  Docker port map (DNAT): 22→2222, 23→2223            │  │  │
│  │  │  Cowrie container (runs as non-root)                 │  │  │
│  │  │     └─ cowrie.json ─► Grafana Alloy ─────────────────┼──┼──┼─► Grafana Cloud
│  │  │                    └► abuse reporter (Phase 6) ──────┼──┼──┼─► AbuseIPDB / DShield
│  │  │  IAM role: AmazonSSMManagedInstanceCore only         │  │  │
│  │  │  IMDSv2 required, hop limit 1                        │  │  │
│  │  └──────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
                                                                     │
       HOME ── browser over HTTPS ── AWS Console (SSM) / Grafana ────┘
       (no VPN, no tunnel, no inbound path to home)
```

## 3. Components

**AWS VPC + Security Group.** The VPC is a private, software-defined network. The security group is a *stateful* firewall attached to the instance. Stateful means return traffic for allowed connections is automatically permitted. Inbound allows only the honeypot ports. Outbound is restricted to 80 and 443 (443 for SSM, log shipping and APIs; 80 because Ubuntu's EC2 package mirrors use plain HTTP). A compromised box therefore can't brute-force SSH/Telnet, send spam (25) or join IRC botnets (6667). The inbound 22/23 rules are only added in Phase 3, once the real OpenSSH server is disabled and Cowrie is listening.

**EC2 `t4g.micro`.** A small ARM (Graviton) VM with 1 GB RAM, which is plenty for Cowrie. ARM is cheaper per hour than the comparable x86 instance.

**SSM Session Manager instead of SSH.** The SSM agent on the instance makes an *outbound* HTTPS connection to AWS. I open a shell through the AWS console or CLI, authenticated by IAM (with MFA), and sessions can be logged. The result: no admin port to brute-force, and port 22 is free for the honeypot. This is the same "no inbound management" idea behind modern EDR/RMM agents.

**IMDSv2 required.** The Instance Metadata Service hands out the instance role's temporary credentials. IMDSv2 requires a session token obtained via PUT, with a hop limit of 1. That blocks the classic SSRF-to-credential-theft attack (the Capital One 2019 breach pattern) and stops containers from reaching metadata.

**Cowrie.** A *medium-interaction* honeypot. It emulates an SSH/Telnet server and a fake Linux shell with a fake filesystem. Attackers can log in and run commands, but nothing actually executes on the host. Cowrie records:
- usernames and passwords tried
- SSH client versions and HASSH fingerprints
- every command typed
- files they try to download (captured and hashed)

Every event is written as structured JSON (`cowrie.login.failed`, `cowrie.command.input`, and so on).
- *Low-interaction* honeypots only log connection attempts.
- *High-interaction* honeypots are real systems, which is riskier.

**Docker port mapping (DNAT).** Binding ports below 1024 requires root. Instead, Cowrie listens on 2222/2223 as an unprivileged user inside its container, and Docker installs a kernel NAT (DNAT) rule mapping host 22→2222 and 23→2223. DNAT preserves the attacker's real source IP. A plain `REDIRECT` to a published port would hand the connection to Docker's userland proxy, and every attacker would appear as `172.17.0.1`. The container also runs with all Linux capabilities dropped, `no-new-privileges`, a read-only root filesystem and memory/PID limits.

**Grafana Alloy.** A log-shipping agent (the successor to Promtail). It tails `cowrie.json`, adds labels, and *pushes* to Grafana Cloud over HTTPS with a token scoped to write logs only. If the host is compromised, the attacker can add junk logs but can't read or delete existing data.

**Grafana Cloud (Loki + Grafana).**
- Loki stores logs and indexes only the labels, not the full text, which keeps it cheap.
- LogQL is the query language, similar in spirit to KQL or SPL.
- Grafana provides the dashboards.
- Tradeoff vs. Elastic/Wazuh/Sentinel: it's a log-analytics platform, not a full SIEM. There's no built-in correlation rules engine and no case management, and free-tier retention is limited. The skills (querying, building detections, dashboarding) transfer directly.

**Abuse reporter (Phase 6).** Reads Cowrie events. It reports only IPs that attempted a login or ran a command, skips an allowlist, and enforces a cooldown. It uses AbuseIPDB categories 18 (Brute-Force) and 22 (SSH), plus 15 (Hacking) or 23 (IoT Targeted) when relevant. It runs in dry-run mode until reviewed.

## 4. Data flow and trust boundaries

| # | Flow | Direction | Protocol | Trust boundary crossed |
|---|---|---|---|---|
| 1 | Attacker → Cowrie | Inbound | SSH/Telnet | Internet → honeypot (untrusted input) |
| 2 | Alloy → Grafana Cloud | Outbound | HTTPS 443 | Honeypot → SaaS (write-only token) |
| 3 | Reporter → AbuseIPDB | Outbound | HTTPS 443 | Honeypot → SaaS (API key) |
| 4 | SSM agent → AWS | Outbound | HTTPS 443 | Honeypot → AWS control plane |
| 5 | Me → AWS console / Grafana | Outbound from home | HTTPS | Home → SaaS (MFA) |

**Nothing initiates a connection toward the home network**, and the honeypot holds no credentials that grant access to anything at home.

## 5. Cost estimate (us-east-1, on-demand)

| Item | ~USD / month |
|---|---|
| EC2 `t4g.micro` | 6.10 |
| Public IPv4 address | 3.65 |
| 20 GB gp3 EBS | 1.60 |
| Data transfer out (under the 100 GB free allowance) | ~0 |
| Grafana Cloud, AbuseIPDB, DShield (free tiers) | 0 |
| **Total** | **~12** |

An AWS Budget alert at $15/month is configured in Phase 1.

## 6. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Escape from Cowrie onto the host | Low | Medium | Emulated shell only; container; non-root; auto security updates; minimal IAM; disposable host |
| Host abused to attack third parties | Low | High | Egress limited to 80/443; Cowrie doesn't execute attacker code; monitor AWS abuse notices |
| AWS account takeover or bill shock | Low | High | Root MFA, no long-lived access keys, IAM Identity Center/MFA, budget alarm |
| Secrets committed to git | Medium | High | `.gitignore`, `.env.example`, gitleaks pre-commit + CI on full history |
| Unsafe handling of captured malware | Medium | Medium | Samples stay on the honeypot; only hashes in repo; never downloaded to work devices |
| Log retention loss (free tier) | High | Low | Weekly summaries and stats committed to `incidents/` |
| Poor-quality or abusive reports to AbuseIPDB | Medium | Medium | Activity threshold, allowlist, cooldown, dry run, rate limits |
| Self-doxxing when the repo goes public | Medium | Medium | Phase 7 redaction checklist (own IPs, account IDs, emails) |

## 7. Decisions log

| Date | Decision | Alternatives considered |
|---|---|---|
| 2026-10-15 | Host on AWS, not home | Home VLAN on UniFi (rejected: exposes home IP, isolation depends on firewall rules being perfect) |
| 2026-10-15 | Grafana Cloud free tier as SIEM | Self-hosted Elastic/Wazuh on second EC2 (~$27–55/mo); Hetzner (cheaper; chose AWS to learn its cloud security controls) |
| 2026-10-15 | SSM instead of admin SSH | SSH on alternate port restricted to home IP (rejected: links home IP to lab, extra attack surface) |
| 2026-10-15 | Egress 80+443 instead of 443 only | 443 only (rejected: Ubuntu EC2 apt mirrors are HTTP; still blocks 22/23/25/6667 abuse) |
| 2026-10-15 | Inbound 22/23 opened in Phase 3, not Phase 2 | Open at launch (rejected: Ubuntu AMI runs real OpenSSH on 22 until disabled) |
| 2026-10-15 | Docker `-p 22:2222` instead of an iptables REDIRECT | REDIRECT + published port (rejected: docker-proxy would mask attacker source IPs) |
| 2026-10-15 | Custom fs.pickle persona (prod-db-02 / dbadmin / postgres) before going live | Stock Cowrie defaults (rejected: `phil`/`svr04` are well-known honeypot fingerprints) |
| 2026-10-15 | Keep Cowrie default userdb (accept almost any login) | Realistic userdb (deferred: build it from observed credential data after ~1 week) |
| 2026-10-28 | Cowrie `mem_limit` 512m → 300m | Keep 512m (rejected: host OOM after ~10 days, IR-2026-003) |
