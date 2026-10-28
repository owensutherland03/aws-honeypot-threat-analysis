# Phase 0: Repository Foundation

**Goal:** Put safety rails in the repo *before* any secret or log exists, so mistakes get caught automatically.

## What was added and why

| File | Purpose | Why it matters |
|---|---|---|
| `.gitignore` | Keeps `.env`, keys, Terraform state, raw logs, malware samples, and reporter DBs out of git | It's easier to never commit a secret than to scrub it later. Once pushed, assume it's compromised and rotate it. |
| `.env.example` | Template listing every secret the project needs, with fake values | Documents configuration without exposing it. This is the standard [12-factor](https://12factor.net/config) pattern: config lives in the environment, not in code. |
| `.pre-commit-config.yaml` | Runs **gitleaks** and other checks before each commit | Shift-left: the mistake is blocked on your machine before it ever leaves. |
| `.github/workflows/secret-scan.yml` | Runs gitleaks in GitHub Actions on the full history for every push/PR | Defense in depth: catches commits from machines without the hook. |
| `docs/architecture.md` | Design, trust boundaries, cost, risk register, decision log | Records why each design choice was made, so future changes have context. |

## Why ignore raw logs?

Raw Cowrie logs contain:
- every attacker IP, which is fine in itself, but can also include your own IP if you test from home
- possibly real credentials that attackers are spraying from breach lists
- file paths to captured malware

The repo will hold **curated, redacted** analysis instead, which is all the analysis needs.

## Do this on your machine (one time)

Install the pre-commit hook on any computer you'll commit from:

```bash
git clone https://github.com/owensutherland03/aws-honeypot-threat-analysis.git
cd aws-honeypot-threat-analysis
pip install pre-commit                    # or: pipx install pre-commit
pre-commit install
pre-commit run --all-files                # first run downloads gitleaks
```

PowerShell (Windows) works the same way with `py -m pip install pre-commit`.

**Test it** with a fake, random-looking GitHub token. Gitleaks deliberately ignores well-known example keys such as AWS's `AKIA...EXAMPLE`, so those don't make a good test.

```powershell
Set-Content test-secret.txt 'token = "ghp_R8kq2LmZx7Vn4TbY1pWc9HsJd3QfUa6EoGi5"'
git add test-secret.txt
git commit -m "test: should be blocked"
```

Expected: `gitleaks....Failed` with a `github-pat` finding, and **no commit is created**. Clean up:

```powershell
git restore --staged test-secret.txt
Remove-Item test-secret.txt
```

## Also check in GitHub settings

- **Repo visibility:** confirm it's **Private** (Settings → General → Danger Zone).
- **Secret scanning / push protection:** on private repos under a personal account this may need a paid plan; it becomes free when the repo goes public. Enable it when you flip to public in Phase 7.
