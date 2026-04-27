# Project Citadel
### Secure Azure Cloud Environment with Monitoring & Threat Detection
**Client:** Nexus Financial Services (Fictional) | **Engineer:** Tobi Babalola

---

## Overview

Project Citadel is an end-to-end Azure cloud security implementation built for Nexus Financial Services — a fictional mid-size fintech standing up its first secure cloud environment. The project covers every layer of cloud security: identity, network, compute, storage, secrets management, logging, threat detection, incident response, compliance enforcement, and infrastructure as code.

Built to reflect real-world security engineering decisions — to understand why each control exists and what breaks without it. Least privilege by default, identity-first architecture, continuous compliance over point-in-time hardening, and a full SOC-style incident response workflow from detection to containment.
**  ---

## Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │           NEXUS FINANCIAL SERVICES           │
                    │              Azure Subscription              │
                    └─────────────────────────────────────────────┘
                                         │
                    ┌────────────────────▼────────────────────────┐
                    │               Citadel-RG                    │
                    │            Region: West US 2                │
                    └─────────────────────────────────────────────┘
                                         │
         ┌───────────────────────────────┼────────────────────────────┐
         │                               │                            │
┌────────▼─────────┐          ┌─────────▼────────┐        ┌─────────▼────────┐
│  IDENTITY LAYER  │          │  NETWORK LAYER   │        │  SECRETS LAYER   │
│                  │          │                  │        │                  │
│  Entra ID        │          │  Citadel-VNet    │        │  Citadel-KV-0    │
│  Abigail Analyst │          │  10.0.0.0/16     │        │  Key Vault       │
│  SecurityTeam    │          │                  │        │  Managed Identity│
│  RBAC: Reader    │          │  PublicSubnet    │        │  Access Policies │
│  MFA: Enabled    │          │  10.0.1.0/24     │        └──────────────────┘
└──────────────────┘          │                  │
                              │  PrivateSubnet   │
                              │  10.0.2.0/24     │
                              │                  │
                              │  Citadel-NSG     │
                              │  Allow SSH: MyIP │
                              │  Deny: All       │
                              └────────┬─────────┘
                                       │
                              ┌────────▼─────────┐
                              │  COMPUTE LAYER   │
                              │                  │
                              │  Citadel-VM      │
                              │  Ubuntu 24.04    │
                              │  SSH Key Auth    │
                              │  Root: Disabled  │
                              │  Passwd: Off     │
                              └────────┬─────────┘
                                       │
                    ┌──────────────────▼──────────────────────────┐
                    │               STORAGE LAYER                  │
                    │                                              │
                    │  citadelstore    │  citadel-data container   │
                    │  TLS 1.2         │  Private Access Only      │
                    │  HTTPS Only      │  Entra ID Auth            │
                    │  No Public Blob  │  No Key Access            │
                    └──────────────────┬──────────────────────────┘
                                       │
                    ┌──────────────────▼──────────────────────────┐
                    │             VISIBILITY LAYER                 │
                    │                                              │
                    │              Citadel-LAW                     │
                    │         Log Analytics Workspace              │
                    │                                              │
                    │  VM Logs (AMA)  │  Storage Diag Settings    │
                    │  Syslog (DCR)   │  Azure Activity Logs      │
                    │  auth/authpriv  │  Heartbeat Alerts         │
                    └──────────────────┬──────────────────────────┘
                                       │
         ┌─────────────────────────────┼──────────────────────────┐
         │                            │                           │
┌────────▼──────────┐      ┌──────────▼──────────┐    ┌──────────▼──────────┐
│  POSTURE LAYER    │      │   DETECTION LAYER    │    │  COMPLIANCE LAYER   │
│                   │      │                      │    │                     │
│  Defender for     │      │  Microsoft Sentinel  │    │  Azure Policy       │
│  Cloud            │      │                      │    │                     │
│  Foundational     │      │  Azure Activity      │    │  SecureTransfer     │
│  CSPM             │      │  Connector           │    │  NetworkAccess      │
│                   │      │  KQL Detection Rule  │    │  PublicAccess       │
│  50/63 controls   │      │  Failed Login Alert  │    │  All: Audit Mode    │
│  0 Critical       │      │  Threshold: 3 hits   │    │                     │
│  0 High findings  │      │  Window: 5 minutes   │    │  Scope: Citadel-RG  │
└───────────────────┘      └──────────────────────┘    └─────────────────────┘
```
<img width="10380" height="4660" alt="Citadel-RG" src="https://github.com/user-attachments/assets/45d98199-d04d-4db3-bff7-2248b3168dae" />

---

## What Was Built

| Layer | Service | Configuration |
|-------|---------|---------------|
| Identity | Entra ID | User, group, RBAC, MFA |
| Network | Virtual Network | VNet, subnets, NSG rules |
| Compute | Virtual Machine | Ubuntu 24.04, SSH key, hardened |
| Storage | Storage Account | Private, HTTPS, Entra ID auth |
| Secrets | Key Vault | Managed identity, access policies |
| Logging | Log Analytics | AMA, DCR, diagnostic settings |
| Alerting | Azure Monitor | Heartbeat alert rule |
| Posture | Defender for Cloud | Foundational CSPM, 50/63 controls |
| SIEM | Microsoft Sentinel | Azure Activity connector, KQL rule |
| Compliance | Azure Policy | 3 policies, Audit mode |
| IaC | ARM Template | Full RG export |

---

## Implementation

### Module 1 — Identity & Access Management

**Objective:** Enforce least privilege and strong authentication before any resource is deployed.

Created a non-admin user `abigail.analyst` in Entra ID — day-to-day operations should never run under a Global Administrator account. Grouped her under `SecurityTeam` for role-based access management at scale. Assigned the `Reader` RBAC role at subscription level — read-only by default, explicit grants required for any write operation. Enabled MFA for all non-admin accounts.

**Key principle:** Identity is the new perimeter. Every access decision flows through Entra ID.
<img width="493" height="269" alt="MFA enabled for Abigail Analyst" src="https://github.com/user-attachments/assets/5f760999-37f2-496f-a66a-74e11e6c95da" />

---

### Module 2 — Network Security

**Objective:** Segment the environment and control all traffic flows explicitly.

Built `Citadel-VNet` with a public and private subnet — workloads with different trust levels never share the same network segment. Deployed `Citadel-NSG` with two inbound rules:

- `Allow-SSH-MyIP` (Priority 100) — SSH allowed only from the engineer's IP
- `Deny-All-Inbound` (Priority 200) — everything else blocked

Associated the NSG to `Citadel-PublicSubnet`. No traffic reaches the VM without explicitly passing through these rules.

> **Note:** West US 2 was selected after East US hit vCPU quota limits on Standard_B1s for the free tier subscription. This is a common real-world constraint — always validate quota before deployment.
<img width="898" height="185" alt="Citadel-NSG inbound rules — Allow-SSH-MyIP + Deny-All-Inbound" src="https://github.com/user-attachments/assets/eda244f6-cedd-41a2-a8cd-9e1ab2de6438" />

---

### Module 3 — VM Deployment & Hardening

**Objective:** Deploy compute inside the secured network boundary and reduce attack surface.

Deployed `Citadel-VM` (Ubuntu 24.04 LTS, Standard_B1s) inside `Citadel-PublicSubnet`. SSH key authentication enforced at deployment — no password auth ever enabled.

Post-deployment hardening:

```bash
# Disable root login
sudo sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config

# Disable password authentication
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# Apply changes
sudo systemctl restart ssh

# Verify
sudo grep -E "PermitRootLogin|PasswordAuthentication" /etc/ssh/sshd_config
```

**Result:** `PermitRootLogin no` | `PasswordAuthentication no`

> **Note:** Ubuntu 24.04 uses `ssh` not `sshd` as the service name. The default `PermitRootLogin` value is `prohibit-password` — not `yes` — requiring a targeted sed replacement.
<img width="571" height="85" alt="Terminal — grep output showing PermitRootLogin no + PasswordAuthentication no" src="https://github.com/user-attachments/assets/f4442df5-77f9-4d95-b755-cfaa4ced2a47" />

---

### Module 4 — Storage Security

**Objective:** Eliminate the most common cloud storage misconfigurations.

Created storage account with four security controls enforced at creation:

| Control | Setting | Why |
|---------|---------|-----|
| Secure transfer | Enabled | Forces HTTPS, no plaintext HTTP |
| Blob public access | Disabled | No anonymous read on any container |
| Storage account key access | Disabled | Eliminates shared key auth, forces Entra ID |
| Minimum TLS | 1.2 | Blocks deprecated TLS 1.0/1.1 |

**Verification:** Uploaded a file to `citadel-data` container, attempted direct URL access — returned `PublicAccessNotPermitted`.
<img width="572" height="178" alt="Browser — PublicAccessNotPermitted error on blob URL" src="https://github.com/user-attachments/assets/74f1d3c9-9e0c-49f6-b559-83031904371f" />

> **Lesson learned:** Disabling storage account key access immediately blocks the portal's default authentication method. Fix: assign `Storage Blob Data Contributor` role to your Entra ID account via IAM before disabling key access. This is exactly why Entra ID auth is superior — every access is identity-bound and auditable.

---

### Module 5 — Secrets Management (Key Vault)

**Objective:** Eliminate hardcoded credentials from compute resources using managed identity.

Created `Citadel-KV-0` with vault access policy permission model. Stored a mock production secret:

```
Name: NovaPay-DB-ConnectionString
Value: Server=nexusfinancial-db.postgres.database.azure.com;Database=novapayprod;User=dbadmin;Password=Citadel@2026!
Type: database/connection-string
```

Enabled system-assigned managed identity on `Citadel-VM`. Granted Key Vault access policy — `Get` and `List` on secrets only. No other permissions. Least privilege applied to secrets access.

**Proof of concept — secret retrieved from VM with zero hardcoded credentials:**

```bash
az login --identity
az keyvault secret show --vault-name Citadel-KV-0 --name NovaPay-DB-ConnectionString --query value -o tsv
```

**Output:** `Server=nexusfinancial-db.postgres.database.azure.com;Database=novapayprod;User=dbadmin;Password=Citadel@2026!`
<img width="681" height="145" alt="Terminal — secret value retrieved showing full connection string" src="https://github.com/user-attachments/assets/62cce9a2-be12-46af-8b92-35de1b56bb00" />

**The chain:** VM → Managed Identity (MSI) → Azure AD Token → Key Vault Access Policy → Secret returned. No passwords stored anywhere on the VM.

---

### Module 6 — Logging & Monitoring

**Objective:** Build full visibility into the environment before threat detection is layered on.

Created `Citadel-LAW` Log Analytics Workspace as the central log destination for all resources.

**VM log collection:**
- Connected VM to workspace via Azure Monitor Agent through Monitoring → Logs
- Created `Citadel-DCR-Syslog` Data Collection Rule targeting `auth` and `authpriv` Syslog facilities at LOG_DEBUG level

> **Note:** Legacy agents management has been removed from newer Log Analytics workspaces. Data Collection Rules are the current method for configuring log collection on Linux VMs.

**Storage log collection:**
- Enabled diagnostic settings on blob service — StorageRead, StorageWrite, StorageDelete → `Citadel-LAW`

**Alerting:**
- Created `Citadel-Alert-VMHeartbeat` — fires when VM stops sending heartbeat signals to workspace
<img width="901" height="377" alt="Log analytics — syslog facility count — authpriv 18, auth 6" src="https://github.com/user-attachments/assets/a46a2833-e448-45ae-b46d-e8b757863fb2" />

---

### Module 7 — Cloud Security Posture (Defender for Cloud)

**Objective:** Continuous automated assessment of the environment against security best practices.

Enabled Foundational CSPM (free tier) on subscription. After assessment completed:

| Metric | Result |
|--------|--------|
| Assessed resources | 6 |
| Critical findings | 0 |
| High findings | 0 |
| MCSB controls passed | 50/63 |
| Compliance domains | NS, IM, PA, DP, AM, LT, IR, PV, ES, BR, DS, GS |

**Known gaps identified by Defender (future improvements):**
- Azure Backup not configured on VM
- Email notifications not enabled for high severity alerts
- Azure Disk Encryption not enabled
- Vulnerability assessment solution not deployed
- Guest Attestation extension not installed

These are documented intentionally 
<img width="748" height="441" alt="Regulatory compliance — 5063 controls passed" src="https://github.com/user-attachments/assets/5de8f86a-5802-4e91-95d0-06e27b91b0b3" />

---

### Module 8 — SIEM (Microsoft Sentinel)

**Objective:** SOC-level detection and alerting on top of the logging pipeline.

Deployed Sentinel connected to `Citadel-LAW`.

**Data connector — Azure Activity:**
Connected via Azure Policy Assignment wizard — streams all subscription-level activity logs into the workspace.

> **Blocker hit:** Remediation task failed — `Microsoft.PolicyInsights` namespace not registered on subscription.
> **Fix:** Registered provider under Subscription → Resource providers, then manually created remediation task.

**Detection rule — Failed Login Attempts:**

```kusto
AzureActivity
| where OperationNameValue contains "signin" or ActivityStatusValue == "Failed"
| where TimeGenerated > ago(5m)
| summarize FailedAttempts = count() by CallerIpAddress, Caller
| where FailedAttempts >= 3
```

- Severity: Medium
- Evaluation frequency: Every 5 minutes
- Incident creation: Enabled
<img width="887" height="232" alt="Analytics rule citadel-rule-failedlogins overview incident simulation-response" src="https://github.com/user-attachments/assets/fae59881-20ff-40a3-b0b4-0a51eb36021f" />

---

### Module 9 — Incident Simulation & Response

**Objective:** Validate the full detection pipeline end-to-end and demonstrate SOC response workflow.

#### Attack Simulation

Executed 15 SSH brute force attempts against `Citadel-VM` using a non-existent key file:

```powershell
for ($i=1; $i -le 15; $i++) {
  ssh -i "wrongkey.pem" -o StrictHostKeyChecking=no -o ConnectTimeout=5 azureuser@20.3.20.191
  Start-Sleep -Seconds 2
}
```

**Result:** 15 × `Permission denied (publickey)` — connection attempts logged on VM.

#### Investigation — VM Side

```bash
sudo journalctl -u ssh --since "1 hour ago" | tail -20
```

**Finding:** All 15 connection resets from `197.210.52.203` confirmed in systemd journal at preauth stage.

> **Note:** Ubuntu 24.04 does not write to `/var/log/auth.log` by default — authentication events are handled by the systemd journal. Use `journalctl -u ssh` instead.

#### Investigation — Log Analytics

```kusto
Syslog
| where Facility == "auth" or Facility == "authpriv"
| where TimeGenerated > ago(1h)
| where SyslogMessage contains "197.210.52.203"
| project TimeGenerated, Facility, SyslogMessage
| order by TimeGenerated desc
```

**Finding:** Attacker IP `197.210.52.203` confirmed in Log Analytics — session events tracked through the cloud-side logging pipeline.

#### MITRE ATT&CK Mapping

| Tactic | Technique | ID | Observed |
|--------|-----------|-----|---------|
| Initial Access | Brute Force: Password Guessing | T1110.001 | 15 failed SSH attempts from single IP |
| Initial Access | Valid Accounts | T1078 | Attacker targeting known account `azureuser` |
| Discovery | Network Service Discovery | T1046 | Reconnaissance implied before targeting port 22 |
| Defense Evasion | Use Alternate Authentication Material | T1550 | Attempted public key bypass |

#### Containment Response

Added NSG inbound deny rule blocking attacker IP:

| Rule | Priority | Source IP | Action |
|------|----------|-----------|--------|
| Allow-SSH-MyIP | 100 | Engineer IP | Allow |
| Deny-Attacker-IP | 105 | 197.210.52.203 | Deny |
| Deny-All-Inbound | 200 | Any | Deny |

**Outcome:** Attacker IP blocked at network layer. Further connection attempts will be dropped before reaching the VM.
<img width="669" height="337" alt="Terminal — journalctl showing connection reset from 197 210 52 203" src="https://github.com/user-attachments/assets/653f2505-8274-48d0-93ec-38b5c5dabde0" />
<img width="907" height="209" alt="NSG inbound rules — all three rules including Deny-Attacker-IP at 105" src="https://github.com/user-attachments/assets/67e2babc-6693-4fdb-8ea8-e633c1d71ae7" />

---

### Module 10 — Compliance Enforcement (Azure Policy)

**Objective:** Convert one-time manual hardening into continuous automated compliance.

Assigned three built-in policies scoped to `Citadel-RG` in Audit mode:

| Policy | Assignment Name | What It Enforces |
|--------|----------------|------------------|
| Secure transfer to storage accounts should be enabled | Citadel-Policy-SecureTransfer | HTTPS-only on all storage |
| Storage accounts should restrict network access | Citadel-Policy-NetworkAccess | No unrestricted network access |
| Storage account public access should be disallowed | Citadel-Policy-StoragePublicAccess | No anonymous blob access |

> All three policies evaluate to **Compliant** against the Citadel storage account — the environment was configured correctly from the start.

**Why Audit mode:** In production, start with Audit to gain visibility before switching to Deny. Jumping straight to Deny in a live environment can break existing non-compliant resources.
<img width="749" height="62" alt="Policy assignments — all three citadel policies listed scoped to Citadel-rg" src="https://github.com/user-attachments/assets/4c1af717-80ea-4931-bbce-7ab1adc6ac5b" />

---

### Module 11 — Infrastructure as Code (ARM Template)

**Objective:** Make the entire environment reproducible — not just documented.

Exported `Citadel-RG` as ARM template via Portal → Resource Groups → Export template.

**Output:**
- `template.json` — full environment definition
- `parameters.json` — parameterised values for redeployment

The portal also generated **Bicep** version of the same infrastructure — both formats available in the `/arm-template` directory.

> **Note:** Export completed with minor errors — some Sentinel-specific resources are not exportable via the portal method. Core infrastructure (VNet, NSG, VM, storage, Key Vault) fully captured.
<img width="856" height="371" alt="Export template page — ARM JSON with resource parameters visible" src="https://github.com/user-attachments/assets/c7cdc8d4-98f4-4899-9460-e4ab494c1a0d" />

---

## Repository Structure

```
project-citadel/
├── README.md
├── arm-template/
│   ├── template.json
│   └── parameters.json
├── screenshots/
│   ├── 01-identity/
│   ├── 02-network/
│   ├── 03-vm-hardening/
│   ├── 04-storage/
│   ├── 05-key-vault/
│   ├── 06-logging/
│   ├── 07-defender/
│   ├── 08-sentinel/
│   ├── 09-incident-response/
│   ├── 10-azure-policy/
│   └── 11-arm-template/
└── incident-report/
    └── citadel-incident-report.md
```

---

## Key Lessons & Hiccups

| Issue | Root Cause | Fix |
|-------|-----------|-----|
| vCPU quota limit in East US | Free tier subscription limits | Rebuilt everything in West US 2 |
| `sshd` service not found | Ubuntu 24.04 uses `ssh` not `sshd` | `sudo systemctl restart ssh` |
| Portal blocked after disabling key access | No Entra ID role on storage | Assigned Storage Blob Data Contributor via IAM |
| Content hub redirecting to Defender portal | Microsoft migrated it permanently | Used defender.microsoft.com for Content hub |
| Remediation task failed on Azure Activity connector | `Microsoft.PolicyInsights` not registered | Registered provider, created task manually |
| Syslog empty on Ubuntu 24.04 | Moved from syslog to systemd journal | Used `journalctl -u ssh` for VM-side investigation |
| Legacy agents management missing | Removed from newer workspaces | Used Data Collection Rules instead |
| Managed identity token endpoint silent | VM deallocated, connectivity lost | Rebooted VM, reinstalled Azure CLI |

---

## Skills Demonstrated

- Azure Identity & Access Management (Entra ID, RBAC, MFA)
- Network segmentation and traffic control (VNet, NSG)
- Linux server hardening (SSH, sshd_config)
- Cloud storage security (access controls, Entra ID auth)
- Secrets management (Key Vault, managed identity)
- Log ingestion and pipeline configuration (AMA, DCR, diagnostic settings)
- Cloud security posture management (Defender for Cloud, MCSB)
- SIEM configuration and KQL detection engineering (Microsoft Sentinel)
- Incident simulation, log investigation, and containment response
- Compliance policy enforcement (Azure Policy)
- Infrastructure as Code (ARM templates, Bicep, Terraform export)
- MITRE ATT&CK framework mapping

---

*Project Citadel — Nexus Financial Services | Built on Microsoft Azure Free Tier*
