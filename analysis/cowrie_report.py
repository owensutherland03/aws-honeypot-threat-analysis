#!/usr/bin/env python3
"""Summarize Cowrie JSON logs for threat analysis (Phase 5).

Streams cowrie.json and its rotated copies (cowrie.json.YYYY-MM-DD) in one
pass, keeping only counters and small per-session summaries, so memory stays
flat however large the logs get. (The first version loaded every event into a
list and was OOM-killed on a 1 GB host after 12 days of data: see IR-2026-003.)
Lines that aren't valid JSON are skipped and counted.

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
from collections import Counter

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
INDICATOR_RX = {name: re.compile(p, re.IGNORECASE) for name, p in INDICATORS.items()}


def stream_events(logdir, exclude, stats):
    """Yield events one at a time; count unparseable lines in stats['bad']."""
    files = sorted(glob.glob(os.path.join(logdir, "cowrie.json*")))
    stats["files"] = len(files)
    for path in files:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    stats["bad"] += 1
                    continue
                if e.get("src_ip") not in exclude:
                    yield e


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
    ev_count, protocols, src_sessions = Counter(), Counter(), Counter()
    creds, users, cmds, clients, hassh, downloads = Counter(), Counter(), Counter(), Counter(), Counter(), Counter()
    download_ips = {}
    indicator_sessions = {name: set() for name in INDICATORS}
    indicator_ips = {name: set() for name in INDICATORS}
    # Per session: [ip, proto, start, command_count, downloads, login, first_3_commands]
    sessions = {}
    ips = set()
    first = last = None

    for e in events:
        ev = e.get("eventid", "")
        ts = e.get("timestamp", "")
        ip = e.get("src_ip")
        if ts:
            first = ts if first is None or ts < first else first
            last = ts if last is None or ts > last else last
        if ip:
            ips.add(ip)
        ev_count[ev] += 1
        sid = e.get("session")
        s = sessions.get(sid)
        if s is None:
            s = sessions[sid] = [ip, e.get("protocol"), ts, 0, 0, None, []]

        if ev == "cowrie.session.connect":
            protocols[e.get("protocol")] += 1
            src_sessions[ip] += 1
        elif ev.startswith("cowrie.login."):
            creds[f'{e.get("username")} / {e.get("password")}'] += 1
            users[e.get("username")] += 1
            if ev == "cowrie.login.success":
                s[5] = f'{e.get("username")}/{e.get("password")}'
        elif ev == "cowrie.command.input" and e.get("input"):
            cmd = e["input"]
            cmds[cmd] += 1
            s[3] += 1
            if len(s[6]) < 3:
                s[6].append(cmd[:60])
            for name, rx in INDICATOR_RX.items():
                if rx.search(cmd):
                    indicator_sessions[name].add(sid)
                    indicator_ips[name].add(ip)
        elif ev.startswith("cowrie.session.file_"):
            key = (e.get("url") or e.get("filename"), e.get("shasum"))
            downloads[key] += 1
            download_ips.setdefault(key, set()).add(ip)
            s[4] += 1
        elif ev == "cowrie.client.version":
            clients[e.get("version")] += 1
        elif ev == "cowrie.client.kex":
            hassh[e.get("hassh")] += 1

    if first is None:
        raise SystemExit("No events found.")
    print("# Cowrie activity summary")
    print(f"  Time span:      {first}  ->  {last}")
    print(f"  Events:         {sum(ev_count.values())}")
    print(f"  Sessions:       {ev_count['cowrie.session.connect']}")
    print(f"  Unique IPs:     {len(ips)}")
    print(f"  Logins ok/fail: {ev_count['cowrie.login.success']} / {ev_count['cowrie.login.failed']}")
    print(f"  Commands:       {ev_count['cowrie.command.input']}")
    print(f"  Downloads:      {ev_count['cowrie.session.file_download']}  "
          f"(failed: {ev_count['cowrie.session.file_download.failed']})  Uploads: {ev_count['cowrie.session.file_upload']}")
    print(f"  Sessions with commands: {sum(1 for s in sessions.values() if s[3])}")

    table("Sessions by protocol", protocols, top)
    table("Top source IPs (sessions)", src_sessions, top)
    table("Top credential pairs", creds, top)
    table("Top usernames", users, top)
    table("Top commands", cmds, top + 15)

    print("\n## Behaviour indicators in commands (sessions / IPs)")
    for name in INDICATORS:
        if indicator_sessions[name]:
            print(f"  {name:<52} {len(indicator_sessions[name]):>6} sessions  {len(indicator_ips[name]):>5} IPs")

    print("\n## Downloads / uploads (URL or filename -> SHA-256)")
    if not downloads:
        print("  (none)")
    for (src, sha), n in downloads.most_common(top):
        print(f"  {n:>4}x  {len(download_ips[(src, sha)])} IP(s)  {src}\n        sha256={sha}")

    table("SSH client versions", clients, top)
    table("HASSH fingerprints", hassh, top)

    print("\n## Most active sessions (by command count)")
    ranked = sorted(((sid, s) for sid, s in sessions.items() if s[3]), key=lambda kv: kv[1][3], reverse=True)
    for sid, (ip, proto, start, n, dl, login, firsts) in ranked[:top]:
        print(f"  {sid}  {ip or '?':<15} {proto or '?':<6} {(start or '')[:19]}  "
              f"cmds={n:<4} dl={dl} login={login}\n        {' | '.join(firsts)}")


def timeline(events, key, value):
    rows = sorted((e for e in events if e.get(key) == value), key=lambda e: e.get("timestamp", ""))
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
        extra = f"  sha256={e['shasum']}" if e.get("shasum") else ""
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
    stats = {"bad": 0, "files": 0}
    events = stream_events(a.logdir, exclude, stats)
    try:
        if a.session:
            timeline(events, "session", a.session)
        elif a.ip:
            timeline(events, "src_ip", a.ip)
        else:
            summary(events, a.top)
            print(f"\n(files: {stats['files']}, unparseable lines skipped: {stats['bad']}, "
                  f"excluded IPs: {', '.join(sorted(exclude))})")
    except BrokenPipeError:  # output piped into `head`
        pass


if __name__ == "__main__":
    main()
