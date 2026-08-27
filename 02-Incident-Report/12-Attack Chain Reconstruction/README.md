# 12. Attack Chain Reconstruction

## 12.1 Reconstruction Objective

This section reconstructs the incident from the available evidence by correlating authentication, process execution, persistence, web activity, database activity, and network communications across the affected assets.

The reconstruction deliberately separates confirmed observations from inferences. Where the available telemetry does not establish the exact mechanism or direction of an action, the event is not presented as fact.

The evidence currently supports a multi-stage compromise involving:

```text
WEB-01
   ↓
Credential / application compromise
   ↓
Web Shell + Persistence
   ↓
PC-MANAGER
   ↓
DC-01
   ↓
C2 / Persistence
   ↓
Repeated access to backup.tar.gz
```

The exact initial-access vector and the precise lateral-movement mechanism remain unresolved.

---

## 12.2 Phase 1 — Initial Access Assessment

The earliest confirmed malicious-looking activity in the supplied timeline is directed against the WordPress authentication interface:

```text
09:00:00 - GET /wp-login.php
09:00:01–09:00:34 - POST /wp-login.php
09:00:35 - GET /wp-admin/
09:00:36 - POST /admin-ajax.php
09:00:37 - GET /backup.tar.gz
```

The repeated POST requests to `/wp-login.php` are consistent with automated credential-guessing activity.

The subsequent access to:

```text
GET /wp-admin/
```

followed immediately by access to:

```text
GET /backup.tar.gz
```

creates a strong temporal relationship between authentication activity and administrative/archive access.

The available evidence therefore supports:

A successful or otherwise effective compromise of the WordPress application occurred before the subsequent administrative and archive-access activity.

However, the logs provided do not expose enough authentication detail to identify the exact credential used or establish whether the WordPress authentication itself was the initial compromise mechanism.

---

## 12.3 Phase 2 — Unauthorized Archive Access

Immediately following the WordPress authentication activity, the archive was requested:

```text
09:00:37
GET /backup.tar.gz
HTTP 200
104857600 bytes
```

This is followed later by a much larger sequence:

```text
09:06:02–09:15:30
GET /backup.tar.gz
Approximately 110 requests
HTTP 200
104857600 bytes per response
```

The repeated retrieval of the same large archive establishes that access to the backup was an important activity during the early compromise.

The theoretical HTTP response volume for approximately 110 complete 100-MiB responses is approximately:

```text
11,534,336,000 bytes
≈ 10.74 GiB
```

This is not treated as confirmed exfiltration volume because the supplied web logs do not establish whether every response was completely transmitted.

The attack chain at this stage is therefore:

```text
WordPress authentication activity
        ↓
Administrative interface access
        ↓
Backup archive access
        ↓
Repeated archive retrieval
```

---

## 12.4 Phase 3 — WEB-01 Host Compromise

The next significant stage is direct host-level access to WEB-01:

```text
09:05:00
Accepted password for www-data from 45.33.22.11
```

followed by:

```text
09:05:01
session opened
```

The attacker then performed host discovery:

```text
09:05:05
whoami && hostname && ip a
```

This sequence is consistent with determining:

* current security context;
* hostname;
* network configuration.

The next activity is payload acquisition:

```text
09:05:10
wget update.sh
```

followed by:

```text
09:05:15
downloading secondary payload
```

and execution:

```text
09:05:20
bash /tmp/update.sh
```

This provides strong evidence that the attacker moved from application-level activity to direct operating-system execution on WEB-01.

The reconstructed sequence is:

```text
External access
     ↓
www-data SSH authentication
     ↓
Interactive session
     ↓
Host/network discovery
     ↓
Payload download
     ↓
Payload execution
```

---

## 12.5 Phase 4 — Defense Impairment and Persistence on WEB-01

Following payload execution, the attacker modified the security posture of the server:

```text
09:05:25
systemctl stop nginx
```

and:

```text
09:05:30
systemctl stop ufw
```

The attacker then modified web-directory permissions:

```text
09:05:35
chmod 777 /var/www/html -R
```

Finally, persistence was established:

```text
09:05:40
echo 'www-data ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
```

This is a critical transition in the attack chain.

The sudoers modification grants www-data passwordless administrative privileges.

Accordingly, the earlier assumption that the attacker merely obtained a low-privileged web account is no longer sufficient to describe the resulting state.

The chain becomes:

```text
www-data access
     ↓
Execution
     ↓
Security controls disabled
     ↓
Web-directory permissions weakened
     ↓
Passwordless sudo persistence
```

This represents privilege escalation/persistence at the host level, although the exact mechanism by which the attacker initially obtained the www-data credentials remains unresolved.

---

## 12.6 Phase 5 — Web Shell Deployment

Immediately afterward, WEB-01 shows direct access to a PHP shell:

```text
09:06:00
GET /shell.php
```

followed by:

```text
09:06:01
POST /shell.php
```

The GET/POST combination is consistent with interaction with a server-side web shell.

The significance is increased by the preceding:

```text
bash /tmp/update.sh
```

and subsequent repeated archive retrieval.

The resulting chain is:

```text
OS-level execution
     ↓
Payload execution
     ↓
Web shell availability
     ↓
Interactive shell access
     ↓
Data access
```

The available logs establish access to `shell.php`, but do not contain the file contents. Therefore, the exact functionality of the shell should not be inferred beyond what the surrounding evidence supports.

---

## 12.7 Phase 6 — Credential and Account Abuse

The incident subsequently shows activity associated with the maryam account.

At 09:20:

```text
09:20:00
GET /wp-admin/
```

followed by:

```text
09:20:01
POST /admin-ajax.php
```

and:

```text
09:20:02
GET /backup.tar.gz
```

The repeated archive retrieval following this sequence is consistent with continued use of the compromised web application.

Later database activity is observed:

```text
09:30
backup: SELECT customers, orders
```

and:

```text
09:35
dbadmin: SELECT wp_users, UPDATE user_pass
```

The `UPDATE user_pass` operation is particularly significant because it indicates modification of WordPress account credentials.

This establishes a second mechanism by which the attacker could maintain or expand access:

```text
Database access
     ↓
wp_users modification
     ↓
Credential modification
     ↓
Potential continued application access
```

The logs do not establish which specific account was modified unless the omitted SQL statement identifies it. Therefore, the report should not claim that maryam's password was definitely changed without the complete query.

---

## 12.8 Phase 7 — Compromise of PC-MANAGER

The next major host-level compromise is associated with PC-MANAGER.

The first relevant authentication event is:

```text
08:07:00
4624
Logon Type 10
User: maryam
Source IP: 192.168.1.100
```

followed by:

```text
08:07:01
4672
Special Privileges
User: maryam
```

Logon Type 10 indicates a Remote Interactive logon.

However, the source address is:

```text
192.168.1.100
```

and the available evidence does not establish that this address represents an external attacker or a separate compromised workstation.

Therefore, the exact movement mechanism remains unresolved.

Later activity on PC-MANAGER is substantially more conclusive:

```text
09:40:00
cmd.exe /c whoami
```

```text
09:40:01
PowerShell -Enc
```

```text
09:40:02
Service Created: SysUpdate
```

```text
09:40:03
svchost.exe → 194.34.132.15:4444
```

This sequence demonstrates malicious execution and persistence on PC-MANAGER.

The reconstructed phase is:

```text
maryam interactive session
        ↓
Privilege-bearing session
        ↓
whoami
        ↓
Encoded PowerShell
        ↓
SysUpdate service
        ↓
C2 connection
```

The evidence strongly supports compromise of PC-MANAGER but does not independently prove that WEB-01 directly initiated the movement.

---

## 12.9 Phase 8 — Command-and-Control Establishment

The external address:

```text
194.34.132.15:4444
```

appears repeatedly after creation of the SysUpdate service.

The Windows firewall logs show:

```text
09:40:03
svchost.exe
Destination: 194.34.132.15:4444
Protocol: TCP
Action: Allow
```

The same process/service behavior later appears on DC-01.

This establishes a strong infrastructure correlation:

```text
PC-MANAGER
    |
    | SysUpdate
    | C:\ProgramData\svchost.exe
    |
    └──── TCP → 194.34.132.15:4444
```

The use of TCP/4444 is suspicious in this context, but the port number alone is not evidence of maliciousness.

The determination is based on the combination of:

```text
Encoded PowerShell
+
Suspicious service creation
+
Executable in C:\ProgramData
+
Repeated external connection
+
Same infrastructure appearing across hosts
```

This combination provides substantially stronger evidence of C2 activity.

---

## 12.10 Phase 9 — Lateral Movement to DC-01

At 20:00, the same operational pattern appears on DC-01.

Authentication:

```text
20:00:00
4624
Logon Type 10
User: maryam
Source IP: 192.168.1.100
```

Privilege assignment:

```text
20:00:01
4672
Special Privileges
User: maryam
```

Command execution:

```text
20:00:02
4688
cmd.exe /c whoami
Parent: explorer.exe
```

Encoded PowerShell:

```text
20:00:03
4688
powershell.exe -Enc
Parent: cmd.exe
```

Persistence:

```text
20:00:04
7045
Service Created: SysUpdate
Image Path:
C:\ProgramData\svchost.exe
Start Type: Auto
```

C2:

```text
20:00:05 onward
5156
C:\ProgramData\svchost.exe
→ 194.34.132.15:4444
TCP
Allow
```

The sequence is effectively a reproduction of the activity previously observed on PC-MANAGER.

This strongly supports a coordinated compromise rather than unrelated administrative activity.

The correct reconstruction is therefore:

```text
Compromised account/session
        ↓
PC-MANAGER compromise
        ↓
Malicious execution + persistence
        ↓
DC-01 access
        ↓
Same execution pattern
        ↓
Same persistence mechanism
        ↓
Same C2 infrastructure
```

The exact protocol used for the lateral movement remains unconfirmed.

---

## 12.11 Phase 10 — Continued Data Access

After the host compromises, the attacker continues interacting with the web application.

At 13:00:

```text
13:00:00
GET /shell.php
```

```text
13:00:01
POST /shell.php
```

followed by:

```text
13:00:02
GET /backup.tar.gz
```

with approximately 49 subsequent archive retrievals.

This provides an important correlation between:

```text
Web Shell
+
Archive
+
Repeated retrieval
```

The archive therefore appears to remain an operational objective throughout the later stages of the intrusion.

At 18:00, the pattern appears again:

```text
18:00:00
GET /wp-admin/
```

```text
18:00:01
POST /admin-ajax.php
```

```text
18:00:02
GET /backup.tar.gz
```

followed by approximately 100 archive retrievals.

This demonstrates continued access to the backup resource well after the initial compromise.

---

## 12.12 Phase 11 — Backup Infrastructure Activity

The final supplied activity occurs at 22:00:

```text
22:00:00
BACKUP-01
4624
Logon Type 3
User: Veeam
Source IP: 172.16.10.50
Share: \BACKUP-01\Backup
```

followed by:

```text
22:00:01–22:00:25
C:\Program Files\Veeam\Backup.exe
→ 172.16.10.50:443
TCP
Allow
```

This activity is not sufficient to classify as malicious.

The process is explicitly associated with:

```text
C:\Program Files\Veeam\Backup.exe
```

and the connection is directed toward an internal address:

```text
172.16.10.50:443
```

The available evidence therefore does not establish that BACKUP-01 was compromised or used for lateral movement.

This event should remain under investigation, particularly because backup infrastructure is a high-value target, but it should not be artificially incorporated into the confirmed malicious chain.

---

## 12.13 Reconstructed Attack Path

Based exclusively on the available evidence, the incident can be represented as:

```text
┌─────────────────────┐
                    │ External Attacker   │
                    └──────────┬──────────┘
                               │
                               │ Initial access
                               │ not conclusively identified
                               ▼
                    ┌─────────────────────┐
                    │      WEB-01         │
                    │ WordPress / Nginx    │
                    └──────────┬──────────┘
                               │
                 ┌─────────────┴─────────────┐
                 │                           │
                 ▼                           ▼
        WordPress access              www-data SSH
        /wp-admin/                    45.33.22.11
                 │                           │
                 │                           ▼
                 │                    Host discovery
                 │                           │
                 │                    update.sh
                 │                           │
                 │                    Web shell
                 │                           │
                 └─────────────┬─────────────┘
                               │
                               ▼
                    backup.tar.gz access
                               │
                               ▼
                    Repeated retrieval
                               │
                               ▼
                    ┌─────────────────────┐
                    │   PC-MANAGER        │
                    │                     │
                    │ maryam / Type 10    │
                    │ cmd.exe             │
                    │ PowerShell -Enc     │
                    │ SysUpdate           │
                    └──────────┬──────────┘
                               │
                               │ Same C2
                               ▼
                    194.34.132.15:4444
                               │
                               ▼
                    ┌─────────────────────┐
                    │       DC-01         │
                    │                     │
                    │ maryam / Type 10    │
                    │ cmd.exe             │
                    │ PowerShell -Enc     │
                    │ SysUpdate           │
                    └──────────┬──────────┘
                               │
                               ▼
                    194.34.132.15:4444
```

---

## 12.14 Confirmed vs. Inferred Chain

| Attack Stage                       | Evidence                                       | Confidence      |
| ---------------------------------- | ---------------------------------------------- | --------------- |
| WordPress authentication attack    | `/wp-login.php` repeated POSTs                 | High            |
| WordPress administrative access    | `/wp-admin/`                                   | High            |
| WEB-01 SSH access                  | Accepted password for www-data                 | Confirmed       |
| Host reconnaissance                | `whoami, hostname, ip a`                       | Confirmed       |
| Payload acquisition                | `wget update.sh`                               | Confirmed       |
| Payload execution                  | `bash /tmp/update.sh`                          | Confirmed       |
| Security-control impairment        | `systemctl stop nginx, systemctl stop ufw`     | Confirmed       |
| Privilege/persistence modification | `www-data ... NOPASSWD: ALL`                   | Confirmed       |
| Web shell access                   | `GET/POST /shell.php`                          | Confirmed       |
| Backup archive access              | `GET /backup.tar.gz, HTTP 200`                 | Confirmed       |
| Potential archive exfiltration     | repeated 100-MiB responses                     | High confidence |
| Credential/database abuse          | `UPDATE user_pass`                             | Confirmed       |
| PC-MANAGER compromise              | Type 10 + malicious execution chain            | High confidence |
| PC-MANAGER persistence             | SysUpdate                                      | Confirmed       |
| PC-MANAGER C2                      | `svchost.exe → 194.34.132.15:4444`             | Confirmed       |
| Lateral movement to DC-01          | correlated Type 10 + identical malicious chain | High confidence |
| Exact lateral-movement protocol    | Not present in supplied evidence               | Unconfirmed     |
| DC-01 persistence                  | SysUpdate                                      | Confirmed       |
| DC-01 C2                           | `svchost.exe → 194.34.132.15:4444`             | Confirmed       |
| BACKUP-01 compromise               | Veeam activity only                            | Not established |

---

## 12.15 Final Reconstruction

The strongest reconstruction supported by the evidence is that the incident evolved from compromise of the externally exposed web environment into host-level control of WEB-01, followed by establishment of persistence and web-shell access. The attacker repeatedly accessed a large backup archive and subsequently demonstrated activity consistent with credential abuse and expansion into internal Windows systems.

PC-MANAGER and DC-01 subsequently exhibited nearly identical malicious execution patterns:

```text
4624 Type 10
→ 4672
→ cmd.exe /c whoami
→ PowerShell -Enc
→ SysUpdate
→ C:\ProgramData\svchost.exe
→ 194.34.132.15:4444
```

The recurrence of this sequence across two systems, combined with the same external destination, provides strong evidence of a coordinated multi-host intrusion.

The principal unresolved questions are the true initial-access vector, the source and acquisition mechanism of the maryam credentials, the exact lateral-movement protocol, and whether the repeated retrievals of `backup.tar.gz` resulted in successful exfiltration of the full theoretical volume.

Accordingly, the incident should currently be characterized as a multi-stage compromise involving WEB-01, subsequent internal host compromise, persistence, C2 establishment, probable lateral movement to DC-01, and high-confidence potential data exfiltration.
