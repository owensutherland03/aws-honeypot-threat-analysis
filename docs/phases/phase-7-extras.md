# Phase 7: Extras & Hardening

Improvements deferred during Phases 0–6, done one at a time.

| # | Item | Status |
|---|---|---|
| 7.1 | "No data" alert: end-to-end pipeline health | ✅ |
| 7.2 | Reporter health alert | ⬜ |
| 7.3 | Fake ELF for `/proc/self/exe` (capture malware downloads) | ⬜ |
| 7.4 | Realistic userdb from observed credentials | ⬜ |
| 7.5 | GeoIP/ASN enrichment | ⬜ |
| 7.6 | Web (HTTP) honeypot | ⬜ |
| 7.7 | Docker user-namespace remapping (GID 999 overlap) | ⬜ |
| 7.8 | Tighten `LabOperator` with IAM Access Analyzer | ⬜ |
| 7.9 | Teardown/rebuild + secret rotation runbooks | ⬜ |
| 7.10 | Pre-publish redaction, license, squash-merge to `main` | ⬜ |

---

## 7.1 "No data" alert

**Why:** a log source that silently stops looks exactly like a quiet day on a dashboard. On 2026-10-15 a stale-looking report briefly raised exactly this question; an alert answers it automatically.

**Design: one end-to-end canary.** The alert queries the *destination* (Loki), so it catches a failure anywhere along the path:

| Failure | Caught? |
|---|---|
| Security group rules removed / instance stopped | ✅ no traffic → no events |
| Cowrie container crashed | ✅ |
| Cowrie writing to the wrong path (mount problem) | ✅ |
| Alloy stopped / misconfigured | ✅ |
| Grafana token expired or revoked, IP restriction mismatch (e.g. new Elastic IP) | ✅ pushes rejected |
| Grafana Cloud ingestion problem | ✅ |

**Query** (Loki, instant):

```logql
sum(count_over_time({job="cowrie"}[2h])) or vector(0)
```

`count_over_time` over an empty range returns *no series at all* rather than `0`. `or vector(0)` turns "nothing" into an explicit `0` the threshold can compare. The rule's no-data state is also set to *Alerting* as a second safety net.

**Rule settings**

| Setting | Value | Why |
|---|---|---|
| Condition | value **is below 1** | zero Cowrie events in the window |
| Window | 2 h | normal traffic is dozens of events per hour; 2 h of silence is abnormal, short gaps are not |
| Evaluation | every 5 min, pending 10 min | avoids alerting on a single odd evaluation |
| No data / error handling | Alerting / Error | missing data must never look "OK" |
| Labels | `severity=warning`, `component=honeypot-pipeline` | routing and grouping |
| Contact point | personal email | |
| Runbook | [`docs/runbooks/no-data-alert.md`](../runbooks/no-data-alert.md) | |

**Testing:** temporarily set the threshold to *is below 1000000* (guaranteed to fire), confirm the email arrives, then set it back. Test alerts by forcing the condition, never by breaking production.

**Result (2026-10-15):** rule `Honeypot: no Cowrie events for 2h` created in folder `Honeypot`, group `honeypot-health` (every 5 m, pending 10 m), contact point `personal-email`. Preview at creation: **505 events in the last 2 h** (≈ 4/min), condition result `0` (false) → *Normal*. Note: in Grafana's condition preview, `1` = condition true = firing, `0` = false.

**Test:** threshold temporarily set to *is below 1000000* with pending `0s` → rule went *Firing* and the alert email was delivered; then reverted to *is below 1* / `10m` → back to *Normal*.

---

## 7.10 Publishing checklist (decided 2026-10-16: keep private for now)

Redaction scan on 2026-10-16 was clean: no sensor/CloudShell IPs, Grafana URL/user/stack IDs, emails, tokens or keys in the tree; attacker IPs are defanged. Before making the repo public:

- [ ] **Persona:** `prod-db-02` / `dbadmin` / kernel `6.1.0-28` are documented in `cowrie/customize_fs.py`, `cowrie/docker-compose.yml`, `docs/architecture.md`, `docs/phases/phase-3-cowrie.md` and IR-2026-001. Publishing them would let anyone fingerprint the live honeypot. Replace them with placeholders, change the live persona, or publish after decommissioning.
- [ ] **History:** squash-merge the working branch into `main` and delete the branch (removes old wording and per-commit session links from public history).
- [ ] Add a license.
- [ ] Enable GitHub secret scanning + push protection.
- [ ] Re-run the redaction scan (IPs, account IDs, emails, hostnames) on `main`.
- [ ] Sharing before then: add specific people as read-only collaborators instead of going public.
