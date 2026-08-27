# 1. Executive Summary

**Incident Date:** 10 June 2025  
**Investigation Window:** 08:05–22:00 UTC  
**Severity:** Critical  
**Incident Type:** Suspected Multi-Stage Compromise  
**Primary Assets:** WEB-01, PC-MANAGER, DC-01  
**Primary External Indicators:** `45.33.22.11`, `194.34.132.15`

---

## Summary

On 10 June 2025, security telemetry identified a sequence of malicious activities affecting multiple systems within the environment. The available evidence indicates a multi-stage intrusion involving compromise of a public-facing WordPress application, execution of attacker-controlled commands, establishment of persistence, command-and-control communications, credential and account manipulation, and subsequent activity involving internal Windows systems.

The earliest high-confidence malicious activity in the available evidence occurs at **09:00 UTC**, when external source `45.33.22.11` repeatedly interacts with the WordPress authentication endpoint on `WEB-01`. The activity consists of repeated `POST` requests to `/wp-login.php`, followed shortly by access to `/wp-admin/` and `admin-ajax.php`, and subsequent requests for `backup.tar.gz`.

### Supporting Evidence

```text
09:00:00 - GET  /wp-login.php
09:00:01–09:00:34 - POST /wp-login.php
09:00:35 - GET  /wp-admin/
09:00:36 - POST /admin-ajax.php
09:00:37 - GET  /backup.tar.gz

Source IP: 45.33.22.11
````

The subsequent activity at **09:05 UTC** on `WEB-01` provides substantially stronger evidence of host compromise. The same external source is associated with an SSH session under the `www-data` account, followed by system reconnaissance, payload retrieval and execution, service disruption, permission modification, and modification of `sudoers`.

### Supporting Evidence

```text
09:05:00 - Accepted password for www-data from 45.33.22.11
09:05:05 - whoami && hostname && ip a
09:05:10 - wget update.sh
09:05:15 - downloading secondary payload
09:05:20 - bash /tmp/update.sh
09:05:25 - systemctl stop nginx
09:05:30 - systemctl stop ufw
09:05:35 - chmod 777 /var/www/html -R
09:05:40 - echo 'www-data ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
```

This sequence is assessed as **confirmed malicious post-compromise activity**.

In particular, modification of `/etc/sudoers` to grant `www-data` passwordless administrative privileges represents a significant privilege-abuse and persistence mechanism.

---

## Web Shell Activity

At **09:06 UTC**, the attacker subsequently accessed `shell.php`:

```text
09:06:00 - GET  /shell.php
09:06:01 - POST /shell.php
```

This activity is consistent with the use of a web-accessible command interface.

The available HTTP logs do not independently establish when or how `shell.php` was created. However, when correlated with the preceding compromise of `WEB-01` and subsequent attacker activity, its use is strongly indicative of malicious web-shell activity.

---

## Backup Archive Access

A further significant finding is repeated access to:

```text
/backup.tar.gz
```

between **09:06 and 09:15 UTC**, with approximately 110 requests recorded and a reported response size of approximately 100 MiB per request.

If every response was fully transferred, the theoretical transferred volume would be approximately **10.74 GiB**.

However, HTTP request logs alone do not establish that the complete volume was successfully received by an external actor. Network-flow, proxy, HTTP transfer-byte, or endpoint telemetry would be required before classifying the activity as **confirmed data exfiltration**.

The current assessment is therefore:

**Data access: Confirmed**
**Successful external exfiltration: Not yet confirmed**

---

## PC-MANAGER Activity

The investigation subsequently identified suspicious activity involving the `maryam` account and `PC-MANAGER`, including encoded PowerShell execution, service creation, and repeated outbound connections to `194.34.132.15:4444`.

### Supporting Evidence

```text
09:40:00 - cmd.exe /c whoami
09:40:01 - PowerShell -Enc
09:40:02 - Service Created: SysUpdate
           Image: C:\ProgramData\svchost.exe
09:40:03 - svchost.exe → 194.34.132.15:4444
```

The combination of encoded PowerShell execution, creation of a new service executing from `C:\ProgramData`, and subsequent outbound communication with an external address constitutes strong evidence of malicious execution, persistence, and probable command-and-control activity.

The same behavioral pattern reappears at **11:00 UTC**:

```text
11:00:00 - 4624 Logon Type 10
11:00:01 - 4672 Special Privileges
11:00:02 - cmd.exe /c whoami
11:00:03 - PowerShell -Enc
11:00:04 - Service Created: SysUpdate
11:00:05 onward - 5156 to 194.34.132.15:4444
```

The recurrence of the same execution, persistence, and network-communication pattern materially increases confidence that the activity represents continued compromise rather than an isolated administrative event.

---

## Correlation With External Infrastructure

At **13:00 UTC**, the external address `194.34.132.15` is directly associated with access to the previously observed web shell and subsequent requests for the backup archive:

```text
13:00:00 - GET  /shell.php
13:00:01 - POST /shell.php
13:00:02 - GET  /backup.tar.gz ×49

Source IP: 194.34.132.15
```

This provides an important correlation between the suspected C2 infrastructure and the compromised web application.

The evidence does not, by itself, establish that `194.34.132.15` was the original source of compromise. However, its direct interaction with the web shell, combined with repeated connections from compromised hosts to `194.34.132.15:4444`, makes the infrastructure a high-priority indicator for investigation and containment.

---

## DC-01 Activity

At **20:00 UTC**, a substantially similar execution and persistence pattern is observed on `DC-01`:

```text
20:00:00 - 4624 Logon Type 10
20:00:01 - 4672 Special Privileges
20:00:02 - cmd.exe /c whoami
20:00:03 - PowerShell -Enc
20:00:04 - Service Created: SysUpdate
20:00:05 onward - C2 connection to 194.34.132.15:4444
```

If the asset attribution and timestamps are accurate, this represents a potential compromise of a **Domain Controller** and materially increases the severity and potential scope of the incident.

Given the role of `DC-01` in the enterprise environment, this finding requires immediate validation through endpoint, identity, and Active Directory telemetry.

---

## Current Assessment

Based on the available evidence, the incident is assessed as a **multi-stage compromise** rather than a collection of unrelated security events.

The strongest currently supported attack sequence is:

```text
WEB-01 Exposure
      ↓
WordPress Authentication Attack
      ↓
WEB-01 Compromise
      ↓
Command Execution
      ↓
Defense Impairment
      ↓
Privilege / Persistence Modification
      ↓
Web Shell
      ↓
Backup Archive Access
      ↓
Internal Host Activity
      ↓
PowerShell Execution
      ↓
Service-Based Persistence
      ↓
C2 Communication
      ↓
Potential Lateral Movement
      ↓
Potential DC-01 Compromise
```

The exact **Initial Access** vector remains unconfirmed.

The `09:00` WordPress attack is the earliest high-confidence malicious activity currently available, but the evidence does not establish whether the attacker initially obtained access through WordPress exploitation, credential compromise, SSH credential compromise, or another mechanism preceding the available logs.

Similarly, the available evidence supports potential data exfiltration involving `backup.tar.gz`, but does not currently prove successful external transfer of the entire observed volume.

The phishing email observed at `09:45 UTC` is therefore **not considered the confirmed Initial Access vector**, because it occurs after the first observed compromise activity on `PC-MANAGER` at `09:40 UTC`.

It should instead be investigated as a possible secondary intrusion attempt, attacker-controlled communication, or evidence of earlier activity not captured in the available dataset.

---

## Incident Determination

| Finding                               | Assessment                                             |
| ------------------------------------- | ------------------------------------------------------ |
| `WEB-01` compromise                   | **Confirmed**                                          |
| Malicious command execution           | **Confirmed**                                          |
| Persistence on `WEB-01`               | **Confirmed**                                          |
| Web-shell activity                    | **High Confidence**                                    |
| C2 activity involving `194.34.132.15` | **High Confidence**                                    |
| Credential/account manipulation       | **High Confidence**                                    |
| Data access involving `backup.tar.gz` | **Confirmed**                                          |
| Successful data exfiltration          | **Not Yet Confirmed**                                  |
| `PC-MANAGER` compromise               | **High Confidence**                                    |
| `DC-01` compromise                    | **High-Impact Finding Requiring Immediate Validation** |
| Phishing as Initial Access            | **Not Established**                                    |
| `10.10.10.200` as malicious source    | **Not Established**                                    |

---

## Overall Assessment

The available evidence is sufficient to classify the environment as an **active Critical security incident** involving confirmed compromise of `WEB-01`, strong evidence of subsequent malicious activity on `PC-MANAGER`, and a potentially significant compromise of `DC-01`.

The observed activity includes attacker-controlled command execution, persistence mechanisms, credential and account manipulation, web-shell access, repeated command-and-control communication, and access to potentially sensitive backup data.

Until endpoint, identity, network, and Active Directory investigations establish the final scope, the environment should be treated as potentially compromised at the **domain level**.

```
```
