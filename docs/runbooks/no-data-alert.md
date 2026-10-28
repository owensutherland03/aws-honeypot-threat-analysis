# Runbook: "Honeypot: no Cowrie events for 2h"

**Meaning:** Grafana Cloud (Loki) has received **zero** Cowrie events for 2 hours. Something between the internet and Loki is broken. Work **outside-in**, stopping at the first failure.

All commands run in an SSM session on `honeypot-01` (`bash` first).

| # | Check | Command / place | Healthy | If not |
|---|---|---|---|---|
| 1 | Instance running | EC2 console → `honeypot-01` | *Running*, 2/2 status checks | Start it; check AWS Health / billing emails |
| 2 | Security group open | EC2 → Security Groups → `honeypot-sg` → Inbound | 22 and 23 from `0.0.0.0/0` | Re-add the rules (they're the "kill switch", so check whether someone closed them on purpose) |
| 3 | Cowrie running | `sudo docker ps --format '{{.Names}} {{.Status}}'` | `cowrie Up …` | `sudo docker logs cowrie --tail 50`; `sudo docker compose -f /opt/cowrie/docker-compose.yml up -d` |
| 4 | Cowrie receiving traffic | `sudo docker logs cowrie --since 30m \| tail` | recent `New connection` lines | Back to 1–2 (network path) |
| 5 | Log file being written | `sudo ls -la --time-style=full-iso /var/log/cowrie/` | `cowrie.json` modified in the last minutes | Check the bind mount: `sudo docker inspect cowrie --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{"\n"}}{{end}}'`; disk: `df -h /` |
| 6 | Alloy running | `systemctl is-active alloy` | `active` | `sudo journalctl -u alloy --since "1 hour ago" \| tail -30` |
| 7 | Alloy reading + sending | `curl -s 127.0.0.1:12345/metrics \| grep -E '^loki_(source_file_read_lines_total\|write_sent_entries_total\|write_request_duration_seconds_count)'` | read ≈ sent, `status_code="204"` growing | `401/403`: token expired/revoked or IP restriction no longer matches the Elastic IP → rotate token / update policy IP ranges |
| 8 | Alloy can read the log | `sudo -u alloy tail -c 100 /var/log/cowrie/cowrie.json >/dev/null && echo ok` | `ok` | Re-apply the ACL (Phase 4, Part B) |
| 9 | Grafana side | Grafana Cloud status page; Explore `{job="cowrie"}` | data present | Wait / contact Grafana support |

**After recovery:** confirm events in Explore, note the cause and duration in the Phase 7 doc, and check whether the reporter missed a window (it only looks back 1 h, so a longer outage means some attackers were never reported).
