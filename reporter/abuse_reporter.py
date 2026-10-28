#!/usr/bin/env python3
"""Report honeypot attackers to AbuseIPDB (Phase 6).

Rules:
  * Only IPs that attempted a login or ran a command are eligible
    (pure port scans are never reported).
  * Skipped: private/reserved addresses, the sensor's own IP, anything in the
    allowlist file, and research scanners identified by forward-confirmed
    reverse DNS (e.g. *.censys-scanner.com) or a scanner SSH client banner.
  * Cooldown: an IP is reported at most once per COOLDOWN_HOURS.
  * Caps: MAX_PER_RUN and MAX_PER_DAY keep us inside the free tier.
  * DRY RUN is the default: prints the reports it *would* send; it never
    contacts AbuseIPDB or writes the state database.

Configuration comes from environment variables (loaded by systemd from
/etc/honeypot-reporter/reporter.env, which is never committed):
  ABUSEIPDB_API_KEY      required when not in dry-run mode
  REPORTER_DRY_RUN       "true" (default) or "false"
  SENSOR_IP              public IP of this honeypot, never reported
  COOLDOWN_HOURS         default 24
  LOOKBACK_HOURS         default 1   (how far back each run looks)
  MAX_PER_RUN            default 50
  MAX_PER_DAY            default 900 (free tier allows 1,000 reports/day)
  LOGDIR                 default /var/log/cowrie
  STATE_DB               default /var/lib/honeypot-reporter/state.db
  ALLOWLIST              default /etc/honeypot-reporter/allowlist.txt

Usage:
  abuse_reporter.py                 # one run with the settings above
  abuse_reporter.py --lookback 24   # override the lookback window (e.g. first dry run)
"""

import argparse
import datetime as dt
import glob
import ipaddress
import json
import os
import socket
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request

API_URL = "https://api.abuseipdb.com/api/v2/report"

# AbuseIPDB category IDs: https://www.abuseipdb.com/categories
CAT_HACKING, CAT_BRUTE_FORCE, CAT_SSH, CAT_IOT = 15, 18, 22, 23

# Research / internet-measurement scanners. Matched against forward-confirmed
# reverse DNS, so an attacker can't just set a PTR record to "shodan.io".
SCANNER_DOMAINS = (
    ".censys-scanner.com", ".shodan.io", ".shadowserver.org", ".binaryedge.ninja",
    ".internet-measurement.com", ".alphastrike.io", ".onyphe.net", ".criminalip.com",
    ".rapid7.com", ".internettl.org", ".stretchoid.com", ".leakix.org",
)
SCANNER_CLIENTS = ("zgrab", "censys", "shodan", "nmap", "masscan")


def env(name, default):
    return os.environ.get(name, default)


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def parse_ts(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


# --------------------------------------------------------------------------- input

def read_events(logdir, since):
    """Yield events newer than `since` from cowrie.json and recent rotated files."""
    for path in sorted(glob.glob(os.path.join(logdir, "cowrie.json*"))):
        if os.path.getmtime(path) < since.timestamp():
            continue  # file last written before the window: nothing new in it
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    e = json.loads(line)
                    if parse_ts(e["timestamp"]) >= since:
                        yield e
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue  # non-JSON lines (e.g. the Phase 4 test artifact)


def aggregate(events):
    """Per source IP: what did it actually do?"""
    ips = {}
    for e in events:
        ip = e.get("src_ip")
        if not ip:
            continue
        a = ips.setdefault(ip, {"protocols": set(), "logins_ok": 0, "logins_fail": 0,
                                "commands": 0, "usernames": set(), "clients": set(),
                                "first": e["timestamp"], "last": e["timestamp"]})
        a["last"] = e["timestamp"]
        if e.get("protocol"):
            a["protocols"].add(e["protocol"])
        ev = e.get("eventid", "")
        if ev == "cowrie.login.success":
            a["logins_ok"] += 1
            a["usernames"].add(str(e.get("username")))
        elif ev == "cowrie.login.failed":
            a["logins_fail"] += 1
            a["usernames"].add(str(e.get("username")))
        elif ev == "cowrie.command.input" and e.get("input"):
            a["commands"] += 1
        elif ev == "cowrie.client.version" and e.get("version"):
            a["clients"].add(e["version"])
    return ips


# ------------------------------------------------------------------- exclusions

def load_allowlist(path):
    nets = []
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    nets.append(ipaddress.ip_network(line, strict=False))
    return nets


def is_research_scanner(ip, clients, check_dns):
    if any(s in c.lower() for c in clients for s in SCANNER_CLIENTS):
        return "research scanner (SSH client banner)"
    if not check_dns:
        return None
    try:
        host = socket.gethostbyaddr(ip)[0].lower()
    except (socket.herror, socket.gaierror, OSError):
        return None
    if not host.endswith(SCANNER_DOMAINS):
        return None
    try:  # forward-confirm: the PTR name must resolve back to the same IP
        if ip in {ai[4][0] for ai in socket.getaddrinfo(host, None)}:
            return f"research scanner ({host})"
    except socket.gaierror:
        pass
    return None


def exclusion_reason(ip, a, allowlist, sensor_ip, check_dns):
    addr = ipaddress.ip_address(ip)
    if not addr.is_global:
        return "private/reserved address"
    if sensor_ip and ip == sensor_ip:
        return "sensor's own IP"
    if any(addr in net for net in allowlist):
        return "allowlisted"
    if a["logins_ok"] + a["logins_fail"] + a["commands"] == 0:
        return "no login attempt or command (scan only)"
    return is_research_scanner(ip, a["clients"], check_dns)


# ------------------------------------------------------------------- reporting

def build_report(ip, a):
    protos = sorted(a["protocols"]) or ["ssh"]
    cats = {CAT_BRUTE_FORCE}
    if "ssh" in protos:
        cats.add(CAT_SSH)
    if "telnet" in protos:
        cats.add(CAT_IOT)
    if a["commands"]:
        cats.add(CAT_HACKING)
    proto_txt = "/".join(p.upper() for p in protos)
    users = ", ".join(sorted(a["usernames"])[:3]) or "n/a"
    parts = [f"Honeypot: {proto_txt} login attempts"]
    n = a["logins_ok"] + a["logins_fail"]
    parts.append(f"({n} attempt{'s' if n != 1 else ''}, users: {users})")
    if a["commands"]:
        parts.append(f"followed by {a['commands']} shell command{'s' if a['commands'] != 1 else ''}")
    parts.append(f"between {a['first'][:16]}Z and {a['last'][:16]}Z.")
    comment = " ".join(parts)[:1000]
    return {"ip": ip, "categories": ",".join(str(c) for c in sorted(cats)),
            "comment": comment, "timestamp": a["last"][:19] + "Z"}


def send_report(report, api_key):
    data = urllib.parse.urlencode(report).encode()
    req = urllib.request.Request(API_URL, data=data, method="POST",
                                 headers={"Key": api_key, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            body = json.load(r)
            return r.status, body.get("data", {}).get("abuseConfidenceScore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")[:200]


# ----------------------------------------------------------------------- state

def open_state(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE IF NOT EXISTS reports (ip TEXT PRIMARY KEY, last_reported TEXT, "
               "times INTEGER DEFAULT 0, last_status TEXT)")
    db.execute("CREATE TABLE IF NOT EXISTS daily (day TEXT PRIMARY KEY, sent INTEGER)")
    return db


def last_reported(db, ip):
    row = db.execute("SELECT last_reported FROM reports WHERE ip=?", (ip,)).fetchone()
    return parse_ts(row[0]) if row else None


def sent_today(db):
    row = db.execute("SELECT sent FROM daily WHERE day=?", (utcnow().date().isoformat(),)).fetchone()
    return row[0] if row else 0


def record(db, ip, status):
    now = utcnow()
    db.execute("INSERT INTO reports (ip, last_reported, times, last_status) VALUES (?,?,1,?) "
               "ON CONFLICT(ip) DO UPDATE SET last_reported=excluded.last_reported, "
               "times=times+1, last_status=excluded.last_status", (ip, now.isoformat(), str(status)))
    db.execute("INSERT INTO daily (day, sent) VALUES (?,1) ON CONFLICT(day) DO UPDATE SET sent=sent+1",
               (now.date().isoformat(),))
    db.commit()


# ------------------------------------------------------------------------ main

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lookback", type=float, help="hours to look back (overrides LOOKBACK_HOURS)")
    ap.add_argument("--no-dns", action="store_true", help="skip reverse-DNS scanner check")
    args = ap.parse_args()

    # Fail safe: anything other than exactly "false" means dry run.
    dry_run = env("REPORTER_DRY_RUN", "true").strip().lower() != "false"
    api_key = env("ABUSEIPDB_API_KEY", "")
    lookback = args.lookback or float(env("LOOKBACK_HOURS", "1"))
    cooldown = dt.timedelta(hours=float(env("COOLDOWN_HOURS", "24")))
    max_run, max_day = int(env("MAX_PER_RUN", "50")), int(env("MAX_PER_DAY", "900"))
    if not dry_run and not api_key:
        sys.exit("ABUSEIPDB_API_KEY is not set; refusing to run in live mode.")

    since = utcnow() - dt.timedelta(hours=lookback)
    ips = aggregate(read_events(env("LOGDIR", "/var/log/cowrie"), since))
    allowlist = load_allowlist(env("ALLOWLIST", "/etc/honeypot-reporter/allowlist.txt"))
    db = None if dry_run else open_state(env("STATE_DB", "/var/lib/honeypot-reporter/state.db"))

    mode = "DRY RUN (nothing is sent)" if dry_run else "LIVE"
    print(f"[{utcnow():%Y-%m-%dT%H:%M:%SZ}] {mode}: {len(ips)} source IPs in the last {lookback:g}h")
    skipped, queued = [], []
    for ip, a in sorted(ips.items(), key=lambda kv: kv[1]["last"]):
        reason = exclusion_reason(ip, a, allowlist, env("SENSOR_IP", ""), not args.no_dns)
        if not reason and db is not None:
            last = last_reported(db, ip)
            if last and utcnow() - last < cooldown:
                reason = f"cooldown (last reported {last:%Y-%m-%d %H:%M}Z)"
        if reason:
            skipped.append((ip, reason))
        else:
            queued.append(build_report(ip, a))

    for ip, reason in skipped:
        print(f"  SKIP   {ip:<15}  {reason}")

    budget = min(max_run, max_day - (sent_today(db) if db else 0))
    if len(queued) > budget:
        print(f"  NOTE   {len(queued) - budget} report(s) deferred by rate caps")
    for r in queued[:max(budget, 0)]:
        if dry_run:
            print(f"  WOULD  {r['ip']:<15}  categories={r['categories']}\n"
                  f"         comment: {r['comment']}")
            continue
        status, info = send_report(r, api_key)
        if status == 200:
            record(db, r["ip"], status)
            print(f"  SENT   {r['ip']:<15}  categories={r['categories']}  confidence={info}")
        elif status == 429 and "15 minutes" in str(info):
            print(f"  SKIP   {r['ip']:<15}  already reported by us in the last 15 min (AbuseIPDB rule)")
        elif status == 429:
            print(f"  STOP   rate limited by AbuseIPDB (429); remaining reports wait for the next run")
            break
        else:  # e.g. 422 validation error; logged, retried next run
            print(f"  FAIL   {r['ip']:<15}  HTTP {status}: {info}")
    print(f"  done: {len(queued)} eligible, {len(skipped)} skipped")


if __name__ == "__main__":
    main()
