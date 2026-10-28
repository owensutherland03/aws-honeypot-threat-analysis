# Phase 1: AWS Account Hardening

**Goal:** A fresh AWS account where the root user is locked away, daily access uses short-lived MFA-protected sessions, and a mistake can't silently become a large bill.

**Network changes:** none. **Cost:** $0.

> Use only **personal** email, phone, card and computer for everything here.
> Don't record your account ID, access-portal URL or MFA recovery details in this repo. Keep them in your password manager.

## Concepts

| Concept | What it is | Analogy |
|---|---|---|
| **Root user** | The email/password that created the account. It can do *anything*, including closing the account and changing billing, and IAM policies can't restrict it. | A break-glass Global Admin |
| **IAM Identity Center** | AWS's built-in identity provider for humans. Users sign in to an access portal and receive **temporary** credentials for a chosen role. | Entra ID sign-in + app role assignments |
| **Permission set** | A template of IAM policies that becomes a role in the account when assigned. | An Entra role definition |
| **AWS Organizations** | Groups AWS accounts under one management account. Identity Center needs it to assign permission sets to accounts. | A tenant |
| **Region** | A physical AWS location. Most resources live in one region. Identity Center is pinned to the region you enable it in. | — |

---

## Part A: Root session (do once, then put root away)

### A1. Create the account
1. Go to `https://aws.amazon.com` → **Create an AWS Account**.
2. Root email: a personal address. A plus-alias like `yourname+aws@gmail.com` keeps AWS mail easy to filter.
3. Account name: something neutral, such as `honeypot-lab`.
4. Choose a **Personal** account and add a personal card.
5. If offered a choice between the **Free plan** (sign-up credits) and the **Paid plan**, pick Free. A Free-plan account is **closed automatically** when the credits or the plan period run out unless you upgrade, so set a calendar reminder for about 5 months from now.
6. Support plan: **Basic** (free).
7. Store the root password in your password manager.

### A2. Turn on MFA for root
1. Sign in as root → account name (top right) → **Security credentials**.
2. **Multi-factor authentication (MFA)** → **Assign MFA device** → name it `root-phone` → **Authenticator app**.
3. Scan the QR code with an authenticator app on your **personal** phone and enter two consecutive codes.
4. *(Recommended)* Register a second MFA device as a backup, such as a passkey or a second authenticator. AWS allows several, and losing your only device means a slow account-recovery process.

**Why:** a root password alone is the single most valuable credential in the account. Credential-stuffing attacks against cloud root accounts are routine.

### A3. Confirm root has no access keys
On the same **Security credentials** page, under **Access keys**, there should be **none**. Never create any. Access keys are long-lived and are the number one way cloud accounts get breached through leaked code.

### A4. Let IAM roles see billing
Account name → **Account** → **IAM user and role access to Billing information** → **Edit** → **Activate**.

**Why:** by default only root can see billing. Turning this on lets your admin role manage budgets, so you don't have to sign in as root again.

### A5. Set the security contact
**Account** page → **Alternate contacts** → **Security** → your personal email.

**Why:** if AWS ever receives abuse reports about your honeypot's IP, this is where they go. You want to see them immediately.

### A6. Choose your region
Top-right region selector → **US East (N. Virginia) `us-east-1`**. It's the cheapest region with the most services, and all cost estimates in this repo assume it. Attack traffic reaches every region, so location barely changes the data.

### A7. Enable IAM Identity Center
1. Search **IAM Identity Center** → **Enable**.
2. Choose **Enable with AWS Organizations**. This creates an organization with your account as the management account.
   - Don't pick an "account instance". Those can't assign permission sets to AWS accounts.
3. **Settings → Authentication → Multi-factor authentication → Configure:**
   - Prompt users for MFA: **Every time they sign in (always-on context)**
   - MFA types: **Authenticator apps** (plus security keys/passkeys if you like)
   - If a user has no MFA device: **Require them to register an MFA device at sign in**

### A8. Create your user
**Users → Add user**
- Username: a short handle (not your work username)
- Email: your personal address
- Leave groups empty for now

Accept the invitation email, set a password (store it in your password manager), and register MFA when prompted. Use a **separate** authenticator entry from root.

### A9. Create the permission sets
**Permission sets → Create permission set**

| Name | Type | Policy | Session duration |
|---|---|---|---|
| `LabAdmin` | Predefined | `AdministratorAccess` | 1 hour |
| `LabOperator` | Predefined | `ReadOnlyAccess` | 4 hours |

`LabOperator` gets an extra inline policy in Phase 2 that allows SSM shell sessions only on instances tagged `Project=honeypot`.

### A10. Assign them
**AWS accounts** → tick your account → **Assign users or groups** → your user → select **both** permission sets → **Submit**.

### A11. Bookmark the portal and sign out of root
**Dashboard** shows the **AWS access portal URL** (`https://d-xxxxxxxxxx.awsapps.com/start`). Bookmark it on your personal computer and save it in your password manager. **Sign out of root.**

From now on, root is used only for account-level emergencies.

---

## Part B: First admin session (through the access portal)

Sign in at your access portal URL → your account → **LabAdmin** → **Management console**.

### B1. Monthly budget alert
**Billing and Cost Management → Budgets → Create budget**
- **Use a template** → **Monthly cost budget**
- Name: `honeypot-monthly`
- Amount: **$15**
- Email recipients: your personal email

The template alerts you when actual spend reaches 85% and 100%, and when **forecasted** spend is on track to exceed 100%.

**Why:** forecast alerts catch a mistake, like a forgotten large instance, days before it shows up on the bill.

### B2. Free Tier usage alerts
**Billing and Cost Management → Billing preferences → Alert preferences → Edit** → enable **AWS Free Tier alerts** → your email.

### B3. Cost Anomaly Detection (free)
**Billing and Cost Management → Cost Anomaly Detection** → create a monitor for **AWS services**, with an individual alert subscription to your email for anomalies over **$5**.

**Why:** budgets catch "too much in total". Anomaly detection catches "unusual for you", such as a sudden spike in data transfer.

### B4. Confirm CloudTrail event history
**CloudTrail → Event history**. You should already see your own sign-ins and the configuration changes from Part A. It's on by default, free, and keeps 90 days of management events.

**Why:** this is the AWS audit log. Find your `ConsoleLogin` event and look at the fields (source IP, user agent, MFA used). This is the same kind of investigation you'd do in Entra sign-in logs.

---

## Verification checklist

- [x] Root has MFA; root has **no** access keys
- [x] IAM access to billing is activated
- [x] Security alternate contact is set
- [x] Identity Center is enabled (organization instance) in `us-east-1` with always-on MFA
- [x] Your user can sign in to the portal with MFA and sees `LabAdmin` and `LabOperator`
- [x] `LabOperator` **can't** create resources (try **EC2 → Launch instance**; you should get an authorization error when you submit)
- [x] `$15` monthly budget exists with forecast alerts
- [x] Free Tier alerts and Cost Anomaly Detection are on
- [x] You found your own `ConsoleLogin` event in CloudTrail
