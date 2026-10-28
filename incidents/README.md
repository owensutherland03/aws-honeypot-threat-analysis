# Incident Reports

Incident-style write-ups of notable honeypot activity. All times UTC. IPs and URLs are **defanged** (`1.2.3[.]4`, `hxxp://`); malware samples are never stored here, only hashes.

| ID | Date | Title | Techniques | Severity (honeypot / real-world) |
|---|---|---|---|---|
| [IR-2026-001](IR-2026-001-telnet-botnet-loader.md) | 2026-10-15 | Telnet IoT botnet loader campaign, 15-minute cadence (updated 10-16) | T1133, T1078.001, T1059.004, T1082, T1083, T1222.002, T1564.001 | Low / High |
| [IR-2026-002](IR-2026-002-multi-protocol-dropper.md) | 2026-10-16 | Multi-protocol IoT dropper, payload server 185.93.89[.]72 (egress-blocked) | T1133, T1078.001, T1059.004, T1082, T1083, T1222.002, T1105, T1070.004 | Low / Critical |

Working notes: [`notes/`](notes/)

## Template

1. **Header:** ID, status, severity, sensor, first/last seen, sources, how it was detected
2. **Summary:** 3–5 sentences a manager can read
3. **Timeline (UTC):** evidence-backed, with session IDs
4. **Analysis:** what happened, how we know (strongest evidence first), confidence levels
5. **Indicators:** defanged, with notes on what each is and isn't
6. **MITRE ATT&CK:** tactic, technique, evidence
7. **Recommended actions:** what a real organization should do
8. **Detection queries:** LogQL that finds this again
