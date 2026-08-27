# 15. Impact Assessment

## 15.1 Assessment Overview

The available evidence indicates a multi-stage compromise affecting multiple security zones and system roles, beginning with unauthorized activity against WEB-01 and subsequently involving PC-MANAGER, DC-01, and potentially database-resident information.

The incident resulted in evidence of:

* Unauthorized access to WEB-01
* Execution of attacker-controlled commands and payloads
* Web-shell activity
* Security-control modification on WEB-01
* Persistence through sudoers
* Credential/account abuse involving maryam
* Repeated Command-and-Control communication with 194.34.132.15:4444
* Malicious service creation on Windows systems
* Access to DC-01
* Access to sensitive database tables
* Repeated retrieval of backup.tar.gz

The evidence therefore supports assessment of the incident as a high-impact compromise with potential domain-level consequences.

---

## 15.2 Affected Assets

### WEB-01

**Evidence:**

```text
09:05:00 - Accepted password for www-data from 45.33.22.11
09:05:10 - wget update.sh
09:05:15 - downloading secondary payload
09:05:20 - bash /tmp/update.sh
09:05:25 - systemctl stop nginx
09:05:30 - systemctl stop ufw
09:05:35 - chmod 777 /var/www/html -R
09:05:40 - echo 'www-data ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
```

The evidence demonstrates that WEB-01 was not merely probed. The attacker obtained authenticated access, executed commands, downloaded and executed additional content, modified security controls, weakened filesystem permissions, and established privileged execution capability through sudoers.

**Impact assessment:** Confirmed host compromise and loss of integrity of the web server.

---

### PC-MANAGER

**Evidence:**

```text
09:40:00 - cmd.exe /c whoami
09:40:01 - PowerShell -Enc
09:40:02 - Service Created: SysUpdate
09:40:03 - svchost.exe → 194.34.132.15:4444
```

The execution of cmd.exe, encoded PowerShell, creation of a suspicious service, and subsequent external communication indicate that PC-MANAGER was under attacker control or was being used to execute attacker-controlled activity.

The repeated recurrence of the same execution pattern later in the incident materially strengthens this assessment.

**Impact assessment:** Confirmed compromise with persistence and C2 activity.

---

### DC-01

**Evidence:**

```text
20:00:00 - 4624 Logon Type 10, User: maryam
20:00:01 - 4672
20:00:02 - cmd /c whoami
20:00:03 - PowerShell -Enc
20:00:04 - Service Created: SysUpdate
20:00:05 - C2 Connection to 194.34.132.15:4444
```

The presence of interactive logon, privileged-token assignment, command execution, encoded PowerShell, service creation, and subsequent C2 communication on the Domain Controller represents the most consequential portion of the observed incident.

**Impact assessment:** DC-01 should be treated as fully compromised until independently disproven. Because the affected asset is a Domain Controller, the potential impact extends beyond the host itself to the broader Active Directory security boundary.

---

## 15.3 Credential and Account Impact

### Compromise of maryam

**Evidence:**

```text
08:07:00 - 4624 Logon Type 10, User: maryam, Source IP: 192.168.1.100
08:07:01 - 4672 Special Privileges, User: maryam
```

Later:

```text
18:00:00 - GET /wp-admin/
18:00:01 - POST /admin-ajax.php
18:00:02 - GET /backup.tar.gz
```

The repeated use of the maryam identity across suspicious activity indicates that the account must be considered potentially compromised.

However, the available evidence does not establish precisely how the credentials were obtained.

---

### WordPress Administrative Credential Impact

**Evidence:**

```text
09:30 - backup: SELECT customers, orders
09:35 - dbadmin: SELECT wp_users, UPDATE user_pass
```

The UPDATE user_pass operation indicates modification of WordPress account credentials.

This represents a direct integrity impact to the application's authentication layer and could enable continued unauthorized access even after the original intrusion vector is removed.

**Impact assessment:** Confirmed account-state manipulation.

---

## 15.4 Persistence Impact

### Linux Persistence

**Evidence:**

```text
09:05:40 - echo 'www-data ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
```

This modification grants www-data passwordless administrative execution capability.

The result is a significant loss of privilege boundaries on WEB-01.

---

### Windows Persistence

**Evidence:**

```text
09:40:02 - Service Created: SysUpdate
Image Path: C:\ProgramData\svchost.exe
```

and later:

```text
20:00:04 - Service Created: SysUpdate
```

The recurrence of the same service name and unusual executable location across systems indicates an apparent persistence mechanism.

**Impact assessment:** Persistence was established across both Linux and Windows portions of the environment.

---

## 15.5 Security-Control Degradation

**Evidence:**

```text
09:05:25 - systemctl stop nginx
09:05:30 - systemctl stop ufw
09:05:35 - chmod 777 /var/www/html -R
```

These actions directly affect system availability, network protection, and filesystem security.

Stopping ufw reduces host-level network controls, while recursive chmod 777 removes meaningful access restrictions from the web root.

**Impact assessment:** Confirmed degradation of host security controls.

---

## 15.6 Data Exposure

### backup.tar.gz

**Evidence:**

```text
09:00:37 - GET /backup.tar.gz
```

and:

```text
09:06:02–09:15:30 - GET /backup.tar.gz
```

and:

```text
13:00:02 - GET backup.tar.gz
```

and:

```text
18:00:02 - GET /backup.tar.gz
```

The file was repeatedly retrieved during multiple suspicious activity windows.

The logs establish repeated successful HTTP retrievals of the backup object. They do not, by themselves, establish that every response body was successfully transferred to completion or that the resulting data was definitively retained by the attacker.

Therefore:

**Data exposure is strongly supported; confirmed exfiltration volume requires additional network/HTTP telemetry.**

---

## 15.7 Database Impact

**Evidence:**

```text
09:30 - backup: SELECT customers, orders
09:35 - dbadmin: SELECT wp_users, UPDATE user_pass
```

The attacker-associated activity includes access to customer/order information and modification of WordPress authentication data.

This creates two distinct impact categories:

1. **Confidentiality:** potential exposure of customer and order data.
2. **Integrity:** unauthorized modification of authentication data.

The available logs do not establish whether the entire database was extracted.

---

## 15.8 Command-and-Control Impact

**Evidence:**

```text
09:40:03 - svchost.exe → 194.34.132.15:4444
```

followed by repeated connections:

```text
09:40:03–09:40:59 - C:\ProgramData\svchost.exe
                         → 194.34.132.15:4444
```

and later:

```text
11:00:05 onward - 5156 → 194.34.132.15:4444
```

and:

```text
20:00:05 - C2 Connection to 194.34.132.15:4444
```

The repeated communication from the suspicious SysUpdate execution context to the same external endpoint indicates sustained attacker-controlled communications.

**Impact assessment:** Persistent external control channel is strongly supported by the available evidence.

---

## 15.9 Availability Impact

The evidence does not demonstrate a prolonged outage of the environment.

However:

```text
09:05:25 - systemctl stop nginx
```

demonstrates an explicit attempt to terminate the web service.

Therefore, service disruption was attempted, but the available evidence is insufficient to quantify its duration or business impact.

---

## 15.10 Domain-Level Impact

The most significant escalation in impact occurs when attacker-associated activity reaches DC-01.

**Evidence:**

```text
20:00:00 - 4624 Logon Type 10, User: maryam
20:00:01 - 4672
20:00:02 - cmd /c whoami
20:00:03 - PowerShell -Enc
20:00:04 - Service Created: SysUpdate
20:00:05 - C2 → 194.34.132.15:4444
```

A Domain Controller represents a central trust authority within a Windows domain.

Consequently, compromise of DC-01 creates potential exposure of:

* Domain authentication infrastructure
* Privileged accounts
* Domain-wide access
* Group and security configuration
* Additional enterprise systems reachable through domain credentials

The provided evidence does not prove that every domain account or every domain-joined host was compromised. Nevertheless, the DC compromise is sufficient to treat the broader domain as potentially exposed pending credential and directory-integrity investigation.

---

## 15.11 Overall Impact Determination

Based strictly on the available evidence, the incident demonstrates impact across confidentiality, integrity, and security-control availability.

| Impact Area              | Assessment              | Basis                                                         |
| ------------------------ | ----------------------- | ------------------------------------------------------------- |
| Web server integrity     | Confirmed               | Payload execution, permission changes, sudoers modification   |
| Host security controls   | Confirmed               | ufw stopped, web-root permissions weakened                    |
| Persistence              | Confirmed               | sudoers modification and SysUpdate service                    |
| Credential integrity     | Confirmed impact        | wp_users / user_pass modification                             |
| Account compromise       | Strongly supported      | Repeated suspicious activity under maryam                     |
| C2                       | Strongly supported      | Repeated connections to 194.34.132.15:4444                    |
| Database confidentiality | Potentially compromised | SELECT customers, orders                                      |
| Backup confidentiality   | Strongly exposed        | Repeated successful GET /backup.tar.gz                        |
| Data exfiltration        | Not fully proven        | HTTP retrieval is proven; completed transfer/retention is not |
| Availability             | Attempted impact        | Nginx termination observed                                    |
| Domain security boundary | Critical exposure       | Attacker-associated activity reached DC-01                    |

---

## Final Impact Assessment

The incident should be classified as a high-impact, multi-host compromise with potential domain-wide consequences.

The strongest confirmed impacts are host compromise, persistence, credential/authentication manipulation, security-control degradation, and sustained C2 activity. The evidence also strongly indicates unauthorized access to sensitive application and backup data.

The principal remaining uncertainty is not whether significant compromise occurred; the evidence is already sufficient to establish that. The principal uncertainty is the ultimate scope of data exposure, credential compromise, and domain-wide access achieved by the attacker. Those questions require additional endpoint, authentication, network-flow, database-audit, and Active Directory telemetry.
