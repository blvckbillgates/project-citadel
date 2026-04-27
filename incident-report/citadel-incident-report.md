
```markdown
# Citadel Incident Report
**Organisation:** Nexus Financial Services  
**Project:** Project Citadel  
**Incident ID:** INC-001  
**Date:** 21 April 2026  
**Severity:** Medium  
**Status:** Resolved  
**Authored by:** Tobi Babalola, Azure Security Engineer  

---

## Executive Summary

On 21 April 2026, a simulated brute force attack was conducted against `Citadel-VM` as part of Project Citadel's security validation exercise.
The attacker IP `197.210.52.203` made 15 consecutive failed SSH authentication attempts within a 4-minute window. The attack was detected via VM-side journal logs and confirmed in Microsoft Sentinel's Log Analytics pipeline.
The threat was contained by adding a targeted deny rule to `Citadel-NSG`, blocking the attacker IP at the network layer before any successful authentication occurred.

No data was accessed. No systems were compromised. 

---

## Timeline

| Time (UTC) | Event |
|------------|-------|
| 11:01:19 | First failed SSH attempt detected from 197.210.52.203 |
| 11:01:54 | Fifth consecutive failed attempt — brute force pattern confirmed |
| 11:15:17 | Second wave — 10 additional failed attempts initiated |
| 11:16:29 | Final failed attempt recorded |
| 11:23:30 | Legitimate engineer session disconnected |
| 11:25:01 | Log Analytics Syslog pipeline confirmed — auth/authpriv events flowing |
| 11:30:00 | Attacker IP identified and blocked via NSG deny rule |

---

## Attack Description

The attacker attempted SSH authentication against `Citadel-VM` (20.3.20.191) using an invalid key file across 15 connection attempts. Each attempt was rejected at the pre-authentication stage — the SSH daemon dropped the connection before any credential exchange completed.

The attack pattern is consistent with the following MITRE ATT&CK techniques:

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|---------|
| Initial Access | Brute Force: Password Guessing | T1110.001 | 15 failed SSH attempts from single source IP in 4-minute window |
| Initial Access | Valid Accounts | T1078 | Attacker targeted `azureuser` — a known valid account on the system |
| Discovery | Network Service Discovery | T1046 | Port 22 targeted directly — implies prior reconnaissance |
| Defense Evasion | Use Alternate Authentication Material | T1550 | Attempted to bypass auth using key-based method |

**Overall Tactic:** TA0001 — Initial Access

---

## Detection

### VM-Side Evidence

Investigated via systemd journal on `Citadel-VM`:

```bash
sudo journalctl -u ssh --since "1 hour ago" | tail -20
```

**Findings:**
```
Apr 20 11:01:19 Citadel-VM sshd[15056]: Connection reset by authenticating user azureuser 197.210.52.203 port 8111 [preauth]
Apr 20 11:01:28 Citadel-VM sshd[15059]: Connection reset by authenticating user azureuser 197.210.52.203 port 9492 [preauth]
Apr 20 11:01:37 Citadel-VM sshd[15106]: Connection reset by authenticating user azureuser 197.210.52.203 port 8139 [preauth]
Apr 20 11:01:45 Citadel-VM sshd[15121]: Connection reset by authenticating user azureuser 197.210.52.203 port 7869 [preauth]
Apr 20 11:01:54 Citadel-VM sshd[15123]: Connection reset by authenticating user azureuser 197.210.52.203 port 9244 [preauth]
```

All 15 attempts confirmed. Source IP: `197.210.52.203`. State: `[preauth]` — authentication never completed.

### Cloud-Side Evidence (Log Analytics)

```kusto
Syslog
| where Facility == "auth" or Facility == "authpriv"
| where TimeGenerated > ago(1h)
| where SyslogMessage contains "197.210.52.203"
| project TimeGenerated, Facility, SyslogMessage
| order by TimeGenerated desc
```

**Findings:** Attacker IP confirmed in Log Analytics — session events tracked through the Syslog pipeline. `authpriv` collected 18 events, `auth` collected 6 events during the incident window.

---

## Root Cause Analysis

The attack was made possible by the VM having a publicly accessible IP address on port 22. While the NSG restricted SSH access to the engineer's IP at the time of original configuration, the engineer's IP had changed between sessions — the NSG was updated to reflect the new IP, inadvertently creating a window where the previous IP restriction was modified.

**Contributing factors:**
- Public IP directly attached to VM — no bastion host or jump server
- SSH exposed on standard port 22 — predictable target
- No automated IP allowlist enforcement via Azure Policy

---

## Containment

Added targeted deny rule to `Citadel-NSG`:

| Rule Name | Priority | Source IP | Port | Action |
|-----------|----------|-----------|------|--------|
| Allow-SSH-MyIP | 100 | Engineer IP | 22 | Allow |
| Deny-Attacker-IP | 105 | 197.210.52.203 | Any | Deny |
| Deny-All-Inbound | 200 | Any | Any | Deny |

The attacker IP is now blocked at the network layer. All further connection attempts from `197.210.52.203` will be dropped before reaching the VM.

---

## Impact Assessment

| Category | Assessment |
|----------|------------|
| Data accessed | None |
| Systems compromised | None |
| Authentication succeeded | No |
| Lateral movement | None |
| Data exfiltration | None |
| Service disruption | None |

**Overall impact: Zero.** The VM hardening controls (SSH key auth, root login disabled, password auth disabled) prevented any successful authentication. The attacker could not progress beyond the pre-authentication stage.

---

## Recommendations

**Immediate:**
- Deploy Azure Bastion as the SSH access method — eliminates public IP exposure entirely
- Implement Just-in-Time VM access via Defender for Cloud — port 22 only opens on explicit request for a defined time window

**Short-term:**
- Move SSH to a non-standard port to reduce automated scanning noise
- Implement fail2ban on the VM to automatically block IPs after repeated failures at the OS level
- Configure Sentinel playbook (Logic Apps) to automatically trigger NSG block rule when the failed login detection rule fires — removes manual response step

**Long-term:**
- Deploy Azure Bastion across all VMs in `Citadel-VNet` — no VM should have a public IP
- Enforce via Azure Policy — deny creation of VMs with public IPs in `Citadel-RG`
- Add IP allowlist enforcement as a Policy — deny NSG rules that allow SSH from `0.0.0.0/0`

---

## Lessons Learned

1. **IP changes break NSG rules silently.** When the engineer's IP changed between sessions, the NSG allow rule had to be manually updated. In a real environment this would be managed via dynamic IP groups or Azure Bastion — never a hardcoded IP.

2. **Ubuntu 24.04 changed auth logging.** Traditional `/var/log/auth.log` investigation returned empty. Authentication events now live in the systemd journal — `journalctl -u ssh` is the correct investigation path on modern Ubuntu.

3. **Pre-auth failures are the right signal.** All 15 attempts were dropped at `[preauth]` state — before any credential exchange. This is the correct behaviour for SSH key-only authentication. A password-enabled VM would have been far more vulnerable.

4. **Detection pipeline worked.** VM journal confirmed the attack. Log Analytics confirmed the IP. Sentinel's detection rule was positioned to fire on future events. The full SOC workflow — detect, investigate, contain — was completed in under 10 minutes.

---

*Incident closed. No further action required.*  
*Project Citadel — Nexus Financial Services*
```
