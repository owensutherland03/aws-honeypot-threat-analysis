# Phase 3: Cowrie Honeypot

**Goal:** Cowrie running in a hardened container, answering on 22 (SSH) and 23 (Telnet), writing JSON logs. Then the security group is opened and the honeypot goes live.

**Network changes:** ⚠️ Part C adds inbound **22 and 23 from `0.0.0.0/0`** to `honeypot-sg`.

Work in an SSM session (LabOperator is fine for Parts A and B; the security group change in Part C needs **LabAdmin**). Run `bash` first.

---

## Concepts

| Concept | What it is |
|---|---|
| **Medium-interaction honeypot** | Emulates a service well enough that attackers log in and type commands, but nothing they run actually executes. Cowrie fakes the shell, filesystem and command output in Python. |
| **Container** | An isolated process with its own filesystem view, network namespace and resource limits, sharing the host kernel. Not a VM: the isolation is weaker, so we add hardening flags. |
| **DNAT port mapping** | `-p 22:2222` makes Docker add a kernel NAT rule that rewrites the destination port. The source IP is preserved, so logs show the real attacker. |
| **Linux capabilities** | Root's powers split into ~40 pieces (bind low ports, change file owners, load kernel modules...). Dropping **all** of them means even a root process inside the container is weak. |
| **unattended-upgrades** | Ubuntu's built-in automatic security patching. |

---

## Part A: Patch the host and install Docker

### A1. Update, add tools, enable automatic reboots for patches

```bash
sudo apt-get update && sudo apt-get -y upgrade
sudo apt-get install -y jq
systemctl is-enabled unattended-upgrades          # expect: enabled
cat /etc/apt/apt.conf.d/20auto-upgrades           # expect both lines = "1"

sudo tee /etc/apt/apt.conf.d/52-honeypot-auto-reboot >/dev/null <<'EOF'
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
EOF
```

(The same file is in [`infra/52-honeypot-auto-reboot`](../../infra/52-honeypot-auto-reboot).)

### A2. Install Docker from Docker's official repository

Ubuntu's own `docker.io` package lags behind. Docker's repo is signed with their GPG key, so apt verifies every package.

```bash
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
```

### A3. Docker daemon defaults

```bash
sudo tee /etc/docker/daemon.json >/dev/null <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "no-new-privileges": true,
  "live-restore": true
}
EOF
sudo systemctl restart docker
sudo docker run --rm hello-world
```

- **Log rotation** stops container stdout filling the disk.
- **`no-new-privileges`** applies to every container by default.
- **`live-restore`** keeps containers running if the Docker daemon restarts (for example, during a Docker update).

**Don't** add `ssm-user` to the `docker` group. Docker group membership is effectively root on the host (you can mount `/` into a container). Typing `sudo` keeps the privilege explicit and logged.

---

## Part B: Run Cowrie (ports still closed)

### B1. Inspect the image before running it

```bash
sudo docker pull cowrie/cowrie:latest
sudo docker image inspect cowrie/cowrie:latest \
  --format 'arch={{.Architecture}} user={{.Config.User}} ports={{json .Config.ExposedPorts}} volumes={{json .Config.Volumes}}'
```

Expect `arch=arm64`, a **non-root** user, ports `2222`/`2223`, and volumes under `/cowrie/cowrie-git/`. If the volume paths differ, update them in the compose file below.

Record the image digest so this exact version can be pinned later:

```bash
sudo docker image inspect cowrie/cowrie:latest --format '{{index .RepoDigests 0}}'
```

### B2. Deploy the compose file

Copy [`cowrie/docker-compose.yml`](../../cowrie/docker-compose.yml) to the host:

```bash
sudo mkdir -p /opt/cowrie
sudo tee /opt/cowrie/docker-compose.yml >/dev/null <<'EOF'
<paste the contents of cowrie/docker-compose.yml here>
EOF
sudo docker compose -f /opt/cowrie/docker-compose.yml up -d
sudo docker ps
sudo docker logs cowrie --tail 20
```

`docker ps` should show `0.0.0.0:22->2222/tcp, 0.0.0.0:23->2223/tcp`. The logs should show Cowrie listening on 2222 and 2223.

**If it crash-loops** with a "read-only file system" error, comment out `read_only: true` and run `up -d` again. Note it in the decision log; that's a tradeoff worth recording.

### B3. Attack it yourself, from inside the host

The security group still blocks the internet, but the host can reach its own port 22:

```bash
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1
# any password except "root" or "123456" (Cowrie's default userdb rejects those)
```

Inside the fake shell, try `uname -a`, `cat /etc/passwd`, `ls /home`, `wget http://example.com`, then `exit`. Notice the hostname `prod-db-02`.

### B4. Find and read the JSON log

```bash
VOL=$(sudo docker volume inspect cowrie_cowrie-var --format '{{.Mountpoint}}')
sudo ls -la "$VOL/log/cowrie/"
sudo tail -n 20 "$VOL/log/cowrie/cowrie.json" | jq -c '{t: .timestamp, e: .eventid, ip: .src_ip, u: .username, p: .password, cmd: .input}'
```

You should see `cowrie.session.connect`, `cowrie.login.success`, `cowrie.command.input`, `cowrie.session.closed`. The source IP will be the Docker bridge (`172.17.0.1`) for this local test only, because traffic from localhost goes through Docker's userland proxy. Internet traffic keeps the real IP.

### B5. Prove containers can't reach instance metadata

```bash
sudo docker run --rm curlimages/curl -s -m 5 -X PUT http://169.254.169.254/latest/api/token \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 60" && echo "REACHABLE (bad)" || echo "blocked (good)"
```

The hop limit of 1 means the metadata reply can't survive the extra hop into the container.

---

## Part B2: Remove Cowrie's default fingerprints (done before going live)

Stock Cowrie is recognizable: user `phil` ("Phil California"), hostname `svr04` in `/etc/hostname`, and a fixed default kernel string. Bots and careful attackers check for these.

**Finding where the defaults live (Cowrie 3.1.2).** The docs' `honeyfs/` folder doesn't exist in 3.x. Enumerating the image showed the bundled data is only:

```
src/cowrie/data/etc/cowrie.cfg.dist
src/cowrie/data/etc/userdb.example
src/cowrie/data/fs.pickle      <- directory tree AND small-file contents
```

Each `fs.pickle` node is `[name, type, uid, gid, size, mode, ctime, contents, target, realfile]`, and file contents are stored inline as bytes. The SSH banner is already modern in 3.x (`OpenSSH_9.2p1 Debian-2+deb12u3`).

**Persona:** `prod-db-02`, a Debian 12 PostgreSQL server.

| Fingerprint | Default | Custom |
|---|---|---|
| Admin user | `phil` / "Phil California" | `dbadmin` / "Database Admin" |
| `/etc/hostname` | `svr04` | `prod-db-02` |
| Kernel (`uname`, `/proc/version`) | `6.1.0-21-amd64`, Debian 6.1.90-1 | `6.1.0-28-amd64`, Debian 6.1.119-1 |
| Database user | none | `postgres` (uid 108) + `/var/lib/postgresql/15` |

**How:** [`cowrie/customize_fs.py`](../../cowrie/customize_fs.py) scans every fake file for the default strings, rewrites them, appends the `postgres` account lines, renames `/home/phil`, re-scans, and **refuses to write if any fingerprint remains**. It runs as a dry run unless an output path is given. The resulting `/opt/cowrie/fs.pickle` is mounted read-only over the default, and the kernel environment variables in the compose file match `/proc/version`.

```bash
sudo python3 -I /opt/cowrie/customize_fs.py /tmp/cowrie-default/src/data/fs.pickle                       # dry run
sudo python3 -I /opt/cowrie/customize_fs.py /tmp/cowrie-default/src/data/fs.pickle /opt/cowrie/fs.pickle # write
```

To get the default `fs.pickle` out of the image (it has no shell, so use `docker cp`):

```bash
sudo docker create --name cowrie-inspect <image@digest>
sudo docker cp cowrie-inspect:/cowrie/cowrie-git/src/cowrie /tmp/cowrie-default/src
sudo docker rm cowrie-inspect
```

**Verified 2026-10-15:** `uname -a`, `/proc/version`, `/etc/hostname`, `ls /home`, `/etc/passwd` and `/var/lib/postgresql` all present one consistent persona; the dry-run scan found 6 default fingerprints and 0 after rewriting.

**Security note on pickle:** unpickling can execute code. It's acceptable here only because the input is Cowrie's own file from a digest-pinned image. Never unpickle untrusted data.

---

## Part C: ⚠️ Go live

### C1. Open the security group (LabAdmin)

**EC2 → Security Groups → `honeypot-sg` → Inbound rules → Edit inbound rules → Add rule ×2**

| Type | Port | Source | Description |
|---|---|---|---|
| SSH | 22 | Anywhere-IPv4 `0.0.0.0/0` | Cowrie SSH |
| Custom TCP | 23 | Anywhere-IPv4 `0.0.0.0/0` | Cowrie Telnet |

The console warns about `0.0.0.0/0` on port 22. For a honeypot that's the point. Everywhere else it's a red flag.

### C2. External test from AWS CloudShell

CloudShell (the `>_` icon in the console's top bar) is a browser terminal running in AWS, so the test never touches your own devices or networks.

```bash
curl -s https://checkip.amazonaws.com        # note this IP: it will appear in the logs
nc -vz -w 5 <ELASTIC_IP> 22                 # expect: succeeded / open
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@<ELASTIC_IP>
```

Log in with any password, run a command, `exit`. Back in the SSM session, confirm the log shows **CloudShell's public IP** as `src_ip`. That proves real source IPs are preserved.

### C3. Watch the internet arrive

```bash
sudo tail -f "$VOL/log/cowrie/cowrie.json" | jq -c 'select(.eventid|test("login|command")) | {t: .timestamp[11:19], e: .eventid, ip: .src_ip, u: .username, p: .password, cmd: .input}'
```

Press `Ctrl+C` to stop. On a new IP the first scanners usually arrive within minutes to a few hours.

---

## Verification checklist

- [x] `unattended-upgrades` enabled; auto-reboot at 04:00 configured
- [x] Docker installed from Docker's repo; daemon.json applied
- [x] Cowrie image is arm64 and runs as a non-root user; digest recorded
- [x] `docker ps` shows `0.0.0.0:22->2222`, `0.0.0.0:23->2223`
- [x] Local SSH test produces `cowrie.login.success` and `cowrie.command.input` events
- [x] Containers can't reach IMDS
- [x] Default fingerprints removed (0 remaining); persona verified in a live session
- [x] SG inbound has only 22 and 23
- [x] CloudShell test shows CloudShell's real IP in the log
- [x] First real attacker events captured

**Went live 2026-10-15 ~18:25 UTC.** External SSH login from CloudShell was logged with CloudShell's public AWS address as `src_ip` (not the Docker bridge), confirming source IPs are preserved. The first unsolicited connection arrived within about a minute of the inbound rules being added (18:24:46 UTC), *before* the CloudShell test.

**First attacker profile (Telnet, residential-ISP address):**
- Connected to Telnet every ~13 s in a tight loop, from a new source port each time.
- Each session: the client answered `WONT NAWS` (it refuses to report a terminal window size, which real terminal clients do; minimal bot clients don't), sent no credentials, and disconnected after a **consistent ~12.8 s**. That's a hard-coded timeout.
- Interpretation: an automated Telnet scanner, most likely an infected IoT device running a Mirai-family bot, probing for a login prompt it recognizes. Worth revisiting: if Cowrie's Telnet prompt doesn't match what these bots expect, they never attempt a login.
- Note: Cowrie logs the **container** port (`dst_port` 2223 = Telnet, 2222 = SSH); use the `protocol` field for dashboards.
