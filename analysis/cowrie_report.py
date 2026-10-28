#!/usr/bin/env python3
"""Summarize Cowrie JSON logs for threat analysis (Phase 5).

Reads cowrie.json and its rotated copies (cowrie.json.YYYY-MM-DD), skips
lines that aren't valid JSON, and prints an analyst-oriented summary.

Usage (on the honeypot):
    sudo python3 -I cowrie_report.py                      # summary
    sudo python3 -I cowrie_report.py --session <id>       # full timeline of one session
    sudo python3 -I cowrie_report.py --ip <addr>          # every session from one IP
Options:
    --logdir DIR      default /var/log/cowrie
    --exclude IP,...  source IPs to ignore (own tests); 172.18.0.1 is always excluded
    --top N           rows per table (default 15)
"""

import argparse
import glob
import json
import os
import re
from collections import Counter, defaultdict

ALWAYS_EXCLUDE = {"172.18.0.1"}  # Docker bridge = our own local tests

# Command keywords that hint at specific attacker behaviour (used for ATT&CK mapping).
INDICATORS = {
    "download (wget/curl/tftp/ftpget)": r"\b(wget|curl|tftp|ftpget)\b",
    "make executable (chmod)": r"\bchmod\b",
    "staging in /tmp, /dev/shm or hidden paths": r"(/tmp\b|/dev/shm|/var/tmp|\./\.|/\.[a-z])",
    "busybox probing": r"\bbusybox\b",
    "system info (uname/cpuinfo/nproc/free/lscpu)": r"\b(uname|cpuinfo|nproc|lscpu|free -|meminfo)\b",
    "user/account discovery (whoami/id/w/last/passwd)": r"\b(whoami|id|last|lastlog)\b|/etc/passwd|^w$",
    "SSH key persistence (authorized_keys)": r"authorized_keys",
    "cron persistence (crontab)": r"\bcrontab\b|/etc/cron",
    "password change (passwd/chpasswd)": r"\b(chpasswd|passwd)\b",
    "cryptomining (xmrig/stratum/miner)": r"(xmrig|stratum\+tcp|minerd|\bminer\b|c3pool|nanopool|monero)",
    "obfuscation (base64/eval)": r"(base64|\beval\b|\\x[0-9a-f]{2})",
    "kill competitors (pkill/kill -9/killall)": r"\b(pkill|killall|kill -9)\b",
    "history/log tampering": r"(history -c|unset HISTFILE|/var/log|rm -rf .*\.bash_history)",
    "router CLI escape (enable/system/shell)": r"^(enable|system|shell|sh|linuxshell)$|ping; sh",
}


def load_events(logdir, exclude):
    files = sorted(glob.glob(os.path.join(logdir, "cowrie.json*")))
    events, bad = [], 0
    for path in files:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    bad += 1
                    continue
                if e.get("src_ip") in exclude:
                    continue
                events.append(e)
    events.sort(key=lambda e: e.get("timestamp", ""))
    return files, events, bad


def table(title, counter, top, headers=("Value", "Count")):
    print(f"\n## {title}")
    if not counter:
        print("  (none)")
        return
    width = min(max(len(str(k)) for k, _ in counter.most_common(top)), 90)
    print(f"  {headers[0]:<{width}}  {headers[1]:>6}")
    for k, v in counter.most_common(top):
        k = str(k).replace("\n", "\\n")
        print(f"  {k[:90]:<{width}}  {v:>6}")


def summary(events, top):
    sessions = defaultdict(lambda: {"ip": None, "proto": None, "start": None, "end": None,
                                    "cmds": [], "login": None, "downloads": 0, "client": None})
    for e in events:
        s = sessions[e.get("session")]
        s["ip"] = s["ip"] or e.get("src_ip")
        s["proto"] = s["proto"] or e.get("protocol")
        s["start"] = s["start"] or e.get("timestamp")
        s["end"] = e.get("timestamp")
        ev = e.get("eventid", "")
        if ev == "cowrie.command.input" and e.get("input"):
            s["cmds"].append(e["input"])
        elif ev == "cowrie.login.success":
            s["login"] = f'{e.get("username")}/{e.get("password")}'
        elif ev.startswith("cowrie.session.file_"):
            s["downloads"] += 1
        elif ev == "cowrie.client.version":
            s["client"] = e.get("version")

    ev_count = Counter(e.get("eventid") for e in events)
    ips = {e.get("src_ip") for e in events if e.get("src_ip")}
    print("# Cowrie activity summary")
    print(f"  Time span:      {events[0]['timestamp']}  ->  {events[-1]['timestamp']}")
    print(f"  Events:         {len(events)}")
    print(f"  Sessions:       {ev_count['cowrie.session.connect']}")
    print(f"  Unique IPs:     {len(ips)}")
    print(f"  Logins ok/fail: {ev_count['cowrie.login.success']} / {ev_count['cowrie.login.failed']}")
    print(f"  Commands:       {ev_count['cowrie.command.input']}")
    print(f"  Downloads:      {ev_count['cowrie.session.file_download']}  Uploads: {ev_count['cowrie.session.file_upload']}")
    print(f"  Sessions with commands: {sum(1 for s in sessions.values() if s['cmds'])}")

    table("Sessions by protocol", Counter(e.get("protocol") for e in events if e.get("eventid") == "cowrie.session.connect"), top)
    table("Top source IPs (sessions)", Counter(e.get("src_ip") for e in events if e.get("eventid") == "cowrie.session.connect"), top)
    logins = [e for e in events if e.get("eventid", "").startswith("cowrie.login.")]
    table("Top credential pairs", Counter(f'{e.get("username")} / {e.get("password")}' for e in logins), top)
    table("Top usernames", Counter(e.get("username") for e in logins), top)
    cmds = [e["input"] for e in events if e.get("eventid") == "cowrie.command.input" and e.get("input")]
    table("Top commands", Counter(cmds), top + 15)

    print("\n## Behaviour indicators in commands (sessions / IPs)")
    for name, pattern in INDICATORS.items():
        rx = re.compile(pattern, re.IGNORECASE)
        hit = [s for s in sessions.values() if any(rx.search(c) for c in s["cmds"])]
        if hit:
            print(f"  {name:<52} {len(hit):>4} sessions  {len({s['ip'] for s in hit}):>4} IPs")

    dl = [e for e in events if e.get("eventid", "").startswith("cowrie.session.file_")]
    print("\n## Downloads / uploads (URL or filename -> SHA-256)")
    if not dl:
        print("  (none)")
    seen = Counter((e.get("url") or e.get("filename"), e.get("shasum")) for e in dl)
    for (src, sha), n in seen.most_common(top):
        ips_for = {e.get("src_ip") for e in dl if (e.get("url") or e.get("filename")) == src and e.get("shasum") == sha}
        print(f"  {n:>3}x  {len(ips_for)} IP(s)  {src}\n        sha256={sha}")

    table("SSH client versions", Counter(e.get("version") for e in events if e.get("eventid") == "cowrie.client.version"), top)
    table("HASSH fingerprints", Counter(e.get("hassh") for e in events if e.get("eventid") == "cowrie.client.kex"), top)

    print("\n## Most active sessions (by command count)")
    ranked = sorted(((sid, s) for sid, s in sessions.items() if s["cmds"]),
                    key=lambda kv: len(kv[1]["cmds"]), reverse=True)
    for sid, s in ranked[:top]:
        first = " | ".join(c[:60] for c in s["cmds"][:3])
        print(f"  {sid}  {s['ip'] or '?':<15} {s['proto'] or '?':<6} {(s['start'] or '')[:19]}  "
              f"cmds={len(s['cmds']):<3} dl={s['downloads']} login={s['login']}\n        {first}")


def timeline(events, key, value):
    rows = [e for e in events if e.get(key) == value]
    if not rows:
        print(f"No events with {key}={value}")
        return
    print(f"# Timeline for {key}={value}  ({len(rows)} events)")
    skip = {"cowrie.client.size", "cowrie.client.var", "cowrie.telnet.option"}
    for e in rows:
        ev = e.get("eventid", "")
        if ev in skip:
            continue
        detail = (e.get("input") or e.get("url") or e.get("message") or "").replace("\n", "\\n")
        extra = ""
        if e.get("shasum"):
            extra = f"  sha256={e['shasum']}"
        print(f"  {e.get('timestamp', '')[:23]}  {e.get('session', ''):<12}  {ev:<32} {detail[:140]}{extra}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--logdir", default="/var/log/cowrie")
    ap.add_argument("--exclude", default="")
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--session")
    ap.add_argument("--ip")
    a = ap.parse_args()
    exclude = ALWAYS_EXCLUDE | {x.strip() for x in a.exclude.split(",") if x.strip()}
    files, events, bad = load_events(a.logdir, exclude)
    if not events:
        raise SystemExit(f"No events found in {a.logdir}")
    if a.session:
        timeline(events, "session", a.session)
    elif a.ip:
        timeline(events, "src_ip", a.ip)
    else:
        print(f"(files: {len(files)}, unparseable lines skipped: {bad}, excluded IPs: {', '.join(sorted(exclude))})\n")
        summary(events, a.top)


if __name__ == "__main__":
    main()
