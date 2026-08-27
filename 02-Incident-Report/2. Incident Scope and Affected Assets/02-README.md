# 2. Incident Scope and Affected Assets

## 2.1 Incident Scope

The observed activity spans multiple systems within the internal environment and demonstrates characteristics of a multi-stage compromise rather than an isolated security event.

The earliest confirmed suspicious activity in the available evidence begins with authentication and administrative activity involving WEB-01, followed by confirmed malicious activity against PC-MANAGER, subsequent access involving DC-01, and suspicious database activity associated with DB-01. Activity involving BACKUP-01 remains insufficiently correlated with the confirmed attack chain and is therefore treated separately.

The available evidence supports the following scope:

- Initial web-facing compromise / unauthorized access: WEB-01
- Subsequent endpoint compromise: PC-MANAGER
- Potential credential abuse and administrative access: identity associated with maryam
- Database-level impact: DB-01
- Potential domain-level compromise: DC-01
- Potential access to backup infrastructure: BACKUP-01
- External infrastructure associated with the intrusion: 45.33.22.11 and 194.34.132.15

The incident includes evidence of:

- Repeated authentication attempts against exposed services
- Successful unauthorized authentication
- Execution of reconnaissance commands
- PowerShell execution using an encoded command
- Payload retrieval and execution
- Service-based persistence
- Firewall/security-control modification
- Web-shell activity
- Repeated access to a sensitive backup archive
- Modification of WordPress authentication data
- Command-and-control communication
- Activity involving a Domain Controller

The evidence therefore warrants investigation as a potential enterprise-wide compromise, with particular attention to credential compromise, persistence, lateral movement, and unauthorized data access.

---

## 2.2 Affected Assets

| Asset | IP Address | Role | Assessment | Evidence |
|---|---|---|---|---|
| WEB-01 | 172.16.10.20 | Web server / WordPress | Confirmed Compromised | Successful external authentication, payload execution, security-control modification, web shell, repeated archive access |
| PC-MANAGER | 192.168.1.100 | Manager workstation | Confirmed Compromised | PowerShell execution, malicious service creation, C2 communication |
| DC-01 | 192.168.1.100* | Domain Controller | High-Confidence Compromise | 4624, 4672, 4688, 7045, and repeated 5156 C2 connections |
| DB-01 | Not explicitly provided | Database server | Potentially Compromised / Impacted | Unauthorized modification of wp_users credentials |
| BACKUP-01 | 172.16.10.60 | Backup server | No confirmed compromise | Veeam activity consistent with legitimate backup operations |

> **Note:** The supplied logs associate `192.168.1.100` with both PC-MANAGER and DC-01. This inconsistency must be resolved during investigation because an IP address should not be assumed to uniquely identify two separate hosts without additional evidence.

---

## 2.3 WEB-01 — Confirmed Compromise

### Relevant Log Evidence

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
````

These events establish unauthorized post-authentication activity on WEB-01. The sequence progresses from host reconnaissance to payload retrieval and execution, followed by disabling security controls and establishing elevated command execution through sudoers.

### Additional Evidence

```text
09:06:00 - GET /shell.php
09:06:01 - POST /shell.php
```

The presence of subsequent requests to `shell.php` provides evidence of a web-accessible command execution mechanism associated with the compromise.

WEB-01 should therefore be treated as a confirmed compromised asset.

---

## 2.4 PC-MANAGER — Confirmed Compromise

### Relevant Log Evidence

```text
09:40:00 - cmd.exe /c whoami
09:40:01 - PowerShell -Enc
09:40:02 - Service Created: SysUpdate
09:40:03 - svchost.exe → 194.34.132.15:4444
```

The combination of encoded PowerShell execution, creation of a previously unidentified service, execution from `C:\ProgramData\svchost.exe`, and immediate outbound communication to an external address is inconsistent with ordinary workstation administration.

This activity is further supported by:

```text
09:40:02 - Service Created: SysUpdate
Image Path: C:\ProgramData\svchost.exe
```

and subsequent repeated connections:

```text
09:40:03 onward
C:\ProgramData\svchost.exe
→ 194.34.132.15:4444
```

The evidence is sufficient to classify PC-MANAGER as a confirmed compromised endpoint, with persistence and command-and-control activity observed.

---

## 2.5 DC-01 — High-Confidence Domain-Level Compromise

### Relevant Log Evidence

```text
20:00:00 - 4624 Logon Type 10
User: maryam

20:00:01 - 4672 Special Privileges
User: maryam

20:00:02 - 4688 Process Create
Image: C:\Windows\System32\cmd.exe
Command: cmd.exe /c whoami

20:00:03 - 4688 Process Create
Image: C:\Windows\System32\powershell.exe
Command: powershell.exe -Enc ...

20:00:04 - 7045 Service Created
Service Name: SysUpdate
Image Path: C:\ProgramData\svchost.exe

20:00:05 onward - 5156
Process: C:\ProgramData\svchost.exe
Destination: 194.34.132.15:4444
```

This sequence reproduces the same execution and persistence pattern previously observed on PC-MANAGER.

The combination of privileged logon, command execution, encoded PowerShell, service creation, and outbound communication to the same external endpoint represents high-confidence evidence of malicious activity on the Domain Controller.

Because DC-01 is a domain-level infrastructure component, compromise of this system materially increases the potential impact of the incident, particularly with respect to credential theft, persistence, and access to other domain-joined systems.

---

## 2.6 DB-01 — Database Integrity at Risk

### Relevant Log Evidence

```text
09:30 - backup: SELECT customers, orders

09:35 - dbadmin:
SELECT wp_users,
UPDATE user_pass
```

The backup account's read activity is not inherently malicious and is consistent with a legitimate backup operation.

The subsequent `dbadmin` activity is materially different. The supplied evidence indicates modification of the WordPress user credential data through an `UPDATE` operation.

This represents a potential integrity violation of the application's authentication datastore and may have enabled continued unauthorized access.

DB-01 should therefore remain within incident scope, although the available evidence does not independently establish how the database account was obtained or whether the database host itself was compromised.

---

## 2.7 BACKUP-01 — No Confirmed Compromise

### Relevant Log Evidence

```text
22:00:00 - 4624 Logon Type 3
User: Veeam
Source IP: 172.16.10.50
Share: \BACKUP-01\Backup

22:00:01 onward - 5156
Process: C:\Program Files\Veeam\Backup.exe
Destination: 172.16.10.50:443
Protocol: TCP
Action: Allow
```

The observed process, account, destination, and communication pattern are consistent with legitimate Veeam backup operations.

There is currently no direct evidence in the supplied logs connecting BACKUP-01 to the malicious infrastructure `194.34.132.15` or to the observed compromise chain.

Accordingly, BACKUP-01 remains in scope for validation but is not classified as compromised based on the current evidence.

---

## 2.8 External Infrastructure Relevant to the Incident

### 45.33.22.11

#### Relevant Evidence

```text
09:00 - GET /wp-login.php
09:00:01–09:00:34 - POST /wp-login.php
09:00:35 - GET /wp-admin/
09:00:37 - GET /backup.tar.gz
```

The same external source is subsequently associated with:

```text
09:05:00 - Accepted password for www-data from 45.33.22.11
```

This establishes a strong relationship between the external source, successful web authentication, and subsequent server-side activity.

### 194.34.132.15

#### Relevant Evidence

```text
09:40:03 - C:\ProgramData\svchost.exe
Destination: 194.34.132.15:4444
```

and:

```text
13:00:00 - GET /shell.php
13:00:01 - POST /shell.php
13:00:02 - GET /backup.tar.gz
```

The endpoint is also observed in repeated outbound connections from the compromised Windows environment.

The available evidence therefore identifies `194.34.132.15` as malicious infrastructure associated with the observed intrusion, although its exact role as C2 infrastructure should be stated as an assessment rather than an absolute fact until corroborated by additional network or endpoint telemetry.

---

## 2.9 Scope Determination

### Confirmed / High Confidence

* WEB-01 compromise
* PC-MANAGER compromise
* Malicious persistence on Windows systems
* Malicious external communication with 194.34.132.15:4444
* Unauthorized web-shell activity
* Unauthorized modification of WordPress authentication data
* Malicious activity involving DC-01

### Potentially Impacted

* DB-01
* maryam credentials
* WordPress administrative credentials
* Domain credentials accessible from compromised systems

### Currently Unconfirmed

* BACKUP-01 compromise
* Exact initial access vector
* Exact lateral movement path between WEB-01, PC-MANAGER, DB-01, and DC-01
* Whether all observed `backup.tar.gz` requests represent complete successful transfers
* Whether 45.33.22.11 and 194.34.132.15 represent the same operator/infrastructure

The incident should consequently be handled as a multi-host intrusion with confirmed compromise of critical infrastructure and unresolved questions surrounding initial access, credential compromise, lateral movement, and data access.

```
```
