# Phase 2: Network & Compute

**Goal:** A dedicated VPC and a hardened EC2 instance that you manage through SSM Session Manager, with **no inbound ports open yet**.

**Network changes:** a new isolated VPC, a security group with **no inbound rules**, and outbound limited to 80/443. **Cost from launch:** about $12/month.

Sign in as **LabAdmin** for all of this. Region: **us-east-1**.

> Why no inbound ports yet? Ubuntu's AWS image ships with the real OpenSSH server listening on port 22. We disable it at first boot (user data below), but we only open 22/23 in Phase 3, once Cowrie is actually listening. Never expose a port before you know exactly what's answering on it.

A CLI equivalent of this phase lives in [`infra/`](../../infra/) for future rebuilds.

---

## Step 1: VPC

**VPC console → Create VPC → "VPC and more"**

| Setting | Value | Why |
|---|---|---|
| Name tag auto-generation | `honeypot` | Every resource gets a recognizable name |
| IPv4 CIDR | `10.20.0.0/16` | Avoids ranges common on home/office networks (`192.168.x`, `10.0.0.0/16`). It isn't strictly needed with no VPN, but it's a good habit. |
| IPv6 | None | Keeps the attack surface and the rules simpler |
| Availability Zones | 1 | One instance, no need for redundancy |
| Public subnets / Private subnets | 1 / 0 | The honeypot must be reachable; nothing else lives here |
| **NAT gateways** | **None** | ⚠️ A NAT gateway costs about $32/month and we don't need one |
| VPC endpoints | None | |
| DNS hostnames / DNS resolution | Enabled / Enabled | Needed for SSM and package installs |

The wizard creates the VPC, one public subnet, an **internet gateway**, and a **route table** with `0.0.0.0/0 → igw-…`. That route is what makes the subnet "public".

**Concepts:**
- **Internet gateway:** the VPC's door to the internet. Without it, nothing in or out.
- **Route table:** decides where traffic leaves to. A "public subnet" is just one whose route table points to an internet gateway.
- **Network ACL (NACL):** a *stateless* subnet-level firewall. We leave the default (allow all) and do filtering in the security group, which is *stateful*. Stateless means you'd need separate rules for return traffic.

## Step 2: Security group

**EC2 console → Security Groups → Create security group**

- Name: `honeypot-sg`. Description: `Honeypot - inbound added in Phase 3`. VPC: `honeypot-vpc`.
- **Inbound rules:** *none* (delete any default rule).
- **Outbound rules:** delete the default "All traffic" rule, then add:

| Type | Port | Destination | Description |
|---|---|---|---|
| HTTPS | 443 | 0.0.0.0/0 | SSM, log shipping, APIs |
| HTTP | 80 | 0.0.0.0/0 | Ubuntu apt mirrors |

**What's still allowed without a rule:** security groups don't filter the Amazon DNS resolver, the Amazon Time Sync service, or the instance metadata service. DNS and NTP keep working.

**What this blocks:** outbound SSH/Telnet scanning (22/23), spam (25), IRC botnet command-and-control (6667), and anything else that isn't web.

## Step 3: IAM role for the instance

**IAM console → Roles → Create role**

- Trusted entity: **AWS service** → **EC2**
- Permissions: **`AmazonSSMManagedInstanceCore`** (only this one)
- Name: `honeypot-ec2-ssm-role`

**Why:** this role lets the SSM agent on the instance register with AWS and receive shell sessions, and nothing else. It has no S3 access, can't read other instances, and has no IAM rights. Even if an attacker stole the role's credentials, they could do almost nothing with them.

## Step 4: Launch the instance

**EC2 console → Instances → Launch instances**

| Setting | Value | Why |
|---|---|---|
| Name | `honeypot-01` | |
| Additional tags | `Project` = `honeypot` (resource types: instances, volumes, network interfaces) | Used for cost tracking and the SSM access policy |
| AMI | **Ubuntu Server 24.04 LTS**, architecture **64-bit (Arm)** | LTS gets security updates until 2029; Arm matches `t4g` |
| Instance type | `t4g.micro` | 2 vCPU / 1 GB, about $6/month |
| **Key pair** | **Proceed without a key pair** | We never SSH in. No private key exists, so none can be stolen. |
| Network settings → **Edit** | VPC `honeypot-vpc`, the public subnet, **Auto-assign public IP: Enable**, **Select existing security group:** `honeypot-sg` | |
| Storage | **20 GiB gp3**, Advanced → **Encrypted: Yes** (default `aws/ebs` key) | Encryption at rest is free; gp3 is cheaper than gp2 |

**Advanced details**

| Setting | Value | Why |
|---|---|---|
| IAM instance profile | `honeypot-ec2-ssm-role` | Lets SSM work |
| Metadata accessible | Enabled | |
| **Metadata version** | **V2 only (token required)** | Blocks SSRF-style credential theft |
| **Metadata response hop limit** | **1** | Containers (one network hop further away) can't reach metadata |
| Allow tags in metadata | Disable | |
| **Credit specification** | **Standard** | `t4g` defaults to *Unlimited*, which can bill extra if CPU stays pegged |
| Detailed CloudWatch monitoring | Disable | Costs extra; not needed |
| **User data** | Paste the contents of [`infra/user-data.sh`](../../infra/user-data.sh) | Disables the real OpenSSH server at first boot |

## Step 5: Elastic IP (stable public address)

**EC2 → Elastic IPs → Allocate Elastic IP address** → tag `Project=honeypot` → **Allocate** → **Actions → Associate** → instance `honeypot-01`.

**Why:** an auto-assigned public IP changes every time the instance stops and starts. A stable IP keeps your data consistent (DShield and AbuseIPDB reports, dashboard history) and costs the same $0.005/hour as any public IPv4. Note: an Elastic IP **still bills while the instance is stopped**. Release it if you ever tear the lab down.

## Step 6: Let LabOperator open SSM sessions (honeypot only)

**IAM Identity Center → Permission sets → `LabOperator` → Inline policy → Edit** → paste [`infra/laboperator-ssm-policy.json`](../../infra/laboperator-ssm-policy.json) → **Save**. When prompted, re-provision to the account.

The policy allows `ssm:StartSession` **only** on instances tagged `Project=honeypot`, using the default shell document. Even if you add other instances to this account later, LabOperator can't get a shell on them.

## Step 7: First shell over SSM and verification

Sign in as **LabOperator** → EC2 → `honeypot-01` → **Connect** → **Session Manager** → **Connect**. It can take about 5 minutes after launch for the agent to register.

Run these checks:

```bash
whoami                                   # ssm-user (has sudo; SSM's default)
cat /etc/os-release | head -2            # Ubuntu 24.04
sudo ss -tlnp                            # nothing listening on :22
systemctl is-enabled ssh.socket ssh.service   # masked / masked

# IMDSv1 must be refused (expect 401)
curl -s -o /dev/null -w "%{http_code}\n" http://169.254.169.254/latest/meta-data/

# IMDSv2 works with a token (expect 200)
TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
curl -s -o /dev/null -w "%{http_code}\n" -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/

# Egress: 443 works, other ports are blocked
curl -sI https://example.com | head -1   # HTTP/2 200
curl -s -m 5 http://portquiz.net:8080 || echo "blocked (expected)"
```

**From your personal computer** (not from the instance), check that nothing answers inbound:

```bash
nc -vz -w 5 <ELASTIC_IP> 22    # should time out
```

On macOS `nc` is built in. On Windows, use `Test-NetConnection <ELASTIC_IP> -Port 22`.

## Verification checklist

- [x] VPC `honeypot-vpc` with 1 public subnet, no NAT gateway
- [x] `honeypot-sg`: **0 inbound rules**, outbound 80 + 443 only
- [x] Instance role has only `AmazonSSMManagedInstanceCore`
- [x] Instance: no key pair, IMDSv2 required, hop limit 1, encrypted gp3, standard credits
- [x] Elastic IP associated
- [x] SSM session works as **LabOperator**
- [x] No listener on 22; IMDSv1 returns 401; port 8080 egress blocked
- [ ] Port 22 times out from outside *(deferred; SG has 0 inbound rules. Will be tested from AWS CloudShell in Phase 3.)*

## Verification results (2026-10-15)

| Check | Result |
|---|---|
| `whoami` | `ssm-user` |
| OS | Ubuntu 24.04.4 LTS |
| Listening TCP | only `127.0.0.53:53` and `127.0.0.54:53` (`systemd-resolved`, loopback only); **nothing on :22** |
| `ssh.socket` / `ssh.service` | `masked` / `masked` |
| IMDSv1 | `401` (refused) |
| IMDSv2 | `200` |
| Egress 443 | `HTTP/2 200` |
| Egress 8080 | blocked |

**Reading `ss -tlnp`:** the *Local Address* column shows exposure. `127.x.x.x` is loopback (reachable only from the host itself). `0.0.0.0` / `[::]` means all interfaces, so those are the listeners to scrutinize.

**Private vs public IP:** the hostname `ip-10-20-x-x` shows the instance only knows its private VPC address. The Elastic IP is translated at AWS's edge (1:1 NAT) and never appears on the host's interface.
