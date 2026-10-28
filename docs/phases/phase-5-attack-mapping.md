# Phase 5: MITRE ATT&CK Mapping & Incident Summaries

**Goal:** Turn raw honeypot events into analyst output. Map observed behaviour to ATT&CK techniques with repeatable LogQL detections, and write incident-style summaries of notable sessions.

**Network changes:** none. **Cost:** $0.

## Workflow

1. **Triage the whole dataset** with [`analysis/cowrie_report.py`](../../analysis/cowrie_report.py) on the honeypot. It reads the live and rotated logs (not limited by Grafana's ~14-day retention), skips our own test IPs, and reports top IPs, credentials, commands, downloads, SSH client fingerprints, behaviour indicators and the most active sessions.
2. **Map behaviour to ATT&CK** in [`detections/attack-mapping.md`](../../detections/attack-mapping.md): each technique gets the evidence pattern, a LogQL query that finds it, and an example from our data.
3. **Pick notable sessions** and pull full timelines (`--session <id>` / `--ip <addr>`).
4. **Write incident summaries** in [`incidents/`](../../incidents/) using a consistent template: summary, timeline (UTC), indicators, ATT&CK techniques, assessment, recommended actions.

## Running the report

```bash
sudo python3 -I /opt/cowrie/cowrie_report.py --exclude <cloudshell-ip>          # summary
sudo python3 -I /opt/cowrie/cowrie_report.py --session <session-id>             # one session
sudo python3 -I /opt/cowrie/cowrie_report.py --ip <attacker-ip>                 # one source
```

`172.18.0.1` (local Docker tests) is always excluded, and lines that aren't JSON (such as the Phase 4 test artifact) are skipped and counted.

## Handling captured data

- Attacker IPs, credentials and commands are fine to record in incident write-ups.
- **Malware samples never leave the honeypot.** Record only the URL (defanged: `hxxp://`, `1.2.3[.]4`) and SHA-256; look hashes up on VirusTotal/MalwareBazaar from a browser.
- Exclude our own IPs (CloudShell) from every published artifact.
