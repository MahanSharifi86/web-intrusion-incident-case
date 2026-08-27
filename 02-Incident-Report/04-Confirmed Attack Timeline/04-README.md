# 4. Confirmed Attack Timeline

## 4.1 Timeline Methodology

This timeline reconstructs the incident using only events directly supported by the supplied telemetry.

The timeline distinguishes between:

* **Observed events** — directly represented in the logs.
* **Correlated activity** — events that can be linked through common identities, hosts, processes, or infrastructure.
* **Unresolved transitions** — points where the available evidence does not establish exactly how the attacker moved from one stage or asset to another.

The timestamps below are presented in chronological order. No event is treated as an initial-access event solely because it appears early in the available dataset.

---

## 4.2 08:05 — SSH Authentication to WEB-01

### Log Evidence

```text
08:05:00 - Accepted password for deploy from 192.168.1.120 port 54321
08:05:01 - Accepted password for webadmin from 192.168.1.100 port 54322
08:05:02 - Accepted password for jenkins from 192.168.1.120 port 54323
```

Three successful SSH authentications occurred against WEB-01 within a two-second interval.

The source ports 54321–54323 are ephemeral client-side ports and, by themselves, do not indicate malicious SSH activity.

The available evidence also does not establish that these sessions were attacker-controlled. The use of different legitimate accounts and internal source addresses is insufficient to classify this activity as malicious.

**Assessment:** Observed authentication activity; currently unconfirmed as part of the intrusion.

---

## 4.3 08:06 — Administrative Activity on WEB-01

### Log Evidence

```text
08:06:00 - deploy: systemctl status nginx
08:06:01 - deploy: systemctl restart nginx
08:06:02 - deploy: nginx -t
08:06:03 - webadmin: cat /var/log/nginx/access.log | grep 404
```

The commands are consistent with routine Nginx administration and troubleshooting.

There is no malicious indicator in these commands when considered independently.

**Assessment:** Benign administrative activity based on available evidence.

---

## 4.4 08:07–08:08 — maryam Interactive Session

### Log Evidence

```text
08:07:00 - 4624 Logon Type 10
User: maryam
Source IP: 192.168.1.100

08:07:01 - 4672 Special Privileges
User: maryam

08:08:00 - Chrome LOG:
https://tosnet.ir/wp-admin/
```

Event ID 4624 with Logon Type 10 indicates a Remote Interactive logon.

Event ID 4672 indicates that the resulting logon was assigned special privileges. It does not, by itself, establish that privilege escalation occurred.

The supplied source address is the same as the local address attributed to the session, so the available evidence is insufficient to determine whether this represented a legitimate user session, an RDP connection, or another mechanism.

The subsequent browser access to the WordPress administration interface establishes application activity but does not independently establish malicious behavior.

**Assessment:** Suspicious identity activity requiring correlation; no confirmed malicious action at this stage.

---

## 4.5 08:15 — WordPress Administrative Activity

### Log Evidence

```text
08:15:00 - GET /wp-admin/
08:15:01 - POST /wp-admin/admin-ajax.php
```

Access to `/wp-admin/` followed by `admin-ajax.php` activity is consistent with normal WordPress administrative functionality.

No malicious payload, anomalous request, or external attacker infrastructure is identified in these two events.

**Assessment:** No confirmed malicious activity.

---

## 4.6 08:30 — Repeated Failed Authentication Against DC-01

### Log Evidence

```text
08:30:00–08:30:20
4625 Logon Type 3
User: Administrator
Source IP: 10.10.10.200
21 failed attempts
```

Twenty-one failed Logon Type 3 authentication attempts against the Administrator account occurred within approximately 20 seconds.

The volume and concentration of failures are consistent with automated authentication attempts and warrant investigation as a potential password-guessing or credential-validation event.

However, the source address 10.10.10.200 is internal. The available evidence therefore does not establish whether this represents an attacker-controlled host, an authorized security scanner, a misconfigured service, or another legitimate internal process.

Importantly, no successful authentication follows these 21 attempts in the supplied evidence.

**Assessment:** Suspicious authentication activity. Potential brute-force/password-spraying behavior, but attacker attribution is not confirmed from the supplied logs.

---

## 4.7 09:00–09:00:37 — WordPress Authentication Attack

### Log Evidence

```text
09:00:00 - GET /wp-login.php
09:00:01–09:00:34 - POST /wp-login.php
09:00:35 - GET /wp-admin/
09:00:36 - POST /admin-ajax.php
09:00:37 - GET /backup.tar.gz
```

The request sequence is materially different from the earlier legitimate-looking WordPress activity.

Thirty-four POST requests against `/wp-login.php` within approximately 34 seconds are consistent with automated credential-guessing activity.

The subsequent transition to:

```text
GET /wp-admin/
```

followed by access to:

```text
GET /backup.tar.gz
```

provides strong evidence that the authentication attack resulted in access to authenticated WordPress functionality.

The supplied logs do not contain the HTTP response codes for every individual login attempt, so the exact successful authentication request cannot be identified from this excerpt alone.

**Assessment:** High-confidence malicious authentication activity followed by apparent successful access to the WordPress administrative interface and access to a sensitive backup artifact.

---

## 4.8 09:05 — Successful SSH Access and Post-Compromise Execution on WEB-01

### Log Evidence

```text
09:05:00 - Accepted password for www-data from 45.33.22.11
09:05:01 - session opened

09:05:05 - whoami && hostname && ip a

09:05:10 - wget update.sh
09:05:15 - downloading secondary payload
09:05:20 - bash /tmp/update.sh
```

The external address 45.33.22.11 was previously observed conducting the WordPress authentication attack.

Five minutes later, the same source successfully authenticated to WEB-01 as `www-data`.

The attacker then executed host-discovery commands and retrieved a script before executing it from `/tmp`.

This creates a strong temporal and infrastructural correlation between the external web attack and subsequent server-side activity.

The `whoami` command also indicates that the operator was explicitly determining the security context of the session.

**Assessment:** Confirmed compromise of WEB-01 with post-authentication reconnaissance, payload delivery, and execution.

---

## 4.9 09:05:25–09:05:40 — Security-Control Modification and Persistence

### Log Evidence

```text
09:05:25 - systemctl stop nginx
09:05:30 - systemctl stop ufw
09:05:35 - chmod 777 /var/www/html -R
09:05:40 - echo 'www-data ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
```

The attacker subsequently modified the compromised host in several significant ways.

Stopping `ufw` represents a direct reduction of host-level network protection.

The recursive permission modification weakens access controls throughout the web root.

The modification of `/etc/sudoers` is the most significant event in this sequence because it attempts to grant `www-data` unrestricted passwordless sudo capability.

These actions are incompatible with ordinary WordPress administration and demonstrate deliberate post-compromise persistence and privilege expansion.

**Assessment:** Confirmed malicious activity and persistence establishment on WEB-01.

---

## 4.10 09:06 — Web-Shell Interaction

### Log Evidence

```text
09:06:00 - GET /shell.php
09:06:01 - POST /shell.php
```

Immediately following the server-side compromise, an external client accessed `shell.php` using both GET and POST requests.

The POST interaction is particularly relevant because web shells commonly expose attacker-controlled functionality through HTTP parameters or request bodies.

The filename alone is not sufficient to prove malicious functionality; however, its position within the established compromise sequence provides strong contextual evidence.

**Assessment:** High-confidence web-shell activity associated with the compromised WEB-01.

---

## 4.11 09:06–09:15 — Repeated Backup Archive Access

### Log Evidence

```text
09:06:02–09:15:30
GET /backup.tar.gz
Approximately 110 requests

HTTP response size:
104857600 bytes per request
```

The attacker repeatedly requested the same backup archive for approximately nine minutes.

The recorded response size is 104,857,600 bytes, equivalent to 100 MiB per logged response.

If every response represents a complete transfer, approximately 10.74 GiB of HTTP response data would have been generated across 110 requests.

However, the access logs alone cannot establish that the full response body was successfully delivered to the attacker on every request.

Therefore, this timeline records repeated unauthorized access to a sensitive backup artifact, while the exact amount of successfully exfiltrated data remains unconfirmed.

**Assessment:** High-confidence unauthorized archive access; confirmed exfiltration volume requires network-level corroboration.

---

## 4.12 09:20 — Continued WordPress Activity Under maryam

### Log Evidence

```text
09:20:00 - GET /wp-admin/
09:20:01 - POST /admin-ajax.php
09:20:02 - GET /backup.tar.gz
```

The same general access pattern previously associated with the attacker appears again under the `maryam` identity.

The sequence alone does not establish that maryam personally performed the activity.

An authenticated username represents an account identity, not necessarily the physical operator behind the session.

Given the preceding compromise and subsequent credential-related activity, this event should be investigated as possible credential abuse.

**Assessment:** Suspicious activity associated with the maryam identity; attribution remains unresolved.

---

## 4.13 09:30–09:35 — Database Access and Authentication-Data Modification

### Log Evidence

```text
09:30 - backup: SELECT customers, orders

09:35 - dbadmin:
SELECT wp_users,
UPDATE user_pass
```

The backup account performs read-only queries consistent with backup operations.

The subsequent `dbadmin` activity is materially more significant because the account accesses `wp_users` and performs an update involving `user_pass`.

This represents a potential modification of WordPress authentication credentials.

The evidence does not establish whether the database host itself was compromised, but it does establish potentially unauthorized modification of application authentication data.

**Assessment:** High-severity integrity event affecting WordPress authentication data.

---

## 4.14 09:40 — Malicious Execution and Persistence on PC-MANAGER

### Log Evidence

```text
09:40:00 - cmd.exe /c whoami

09:40:01 - PowerShell -Enc

09:40:02 - Service Created: SysUpdate
             Image Path: C:\ProgramData\svchost.exe

09:40:03 - svchost.exe
             → 194.34.132.15:4444
```

This sequence represents a distinct malicious execution chain.

The operator first determines the current security context using `whoami`, followed by execution of an encoded PowerShell command.

A service named `SysUpdate` is then created using:

```text
C:\ProgramData\svchost.exe
```

The executable immediately establishes outbound communication with 194.34.132.15:4444.

The malicious nature of this sequence is supported by the correlation between process creation, persistence, suspicious executable location, encoded PowerShell, and external network communication.

**Assessment:** Confirmed compromise of PC-MANAGER with persistence and likely command-and-control capability.

---

## 4.15 09:45 — Malicious Email Delivery

### Log Evidence

```text
09:45:03–09:45:07
From: 194.34.132.15
Attachment: invoice_pdf.exe
```

An executable attachment was delivered from the same external infrastructure previously associated with suspicious C2 activity.

The timing is significant: malicious execution on PC-MANAGER had already begun at approximately 09:40.

Consequently, this event cannot currently be identified as the initial access vector for the 09:40 compromise.

It may represent a secondary payload-delivery attempt, a subsequent stage of the intrusion, or a separate malicious email event.

**Assessment:** Malicious delivery activity; initial-access attribution not established.

---

## 4.16 11:00 — Repeated Malicious Execution Pattern

### Log Evidence

```text
11:00:00 - Logon Type 10
11:00:01 - 4672
11:00:02 - cmd /c whoami
11:00:03 - PowerShell -Enc
11:00:04 - Service Created: SysUpdate
```

The same behavioral sequence observed at 09:40 reappears at 11:00.

The combination of interactive logon, special privileges, command execution, encoded PowerShell, and creation of the same `SysUpdate` service indicates persistence or re-establishment of the attacker-controlled execution chain.

The recurrence substantially increases confidence that the earlier activity was not an isolated administrative anomaly.

**Assessment:** High-confidence continuation of the intrusion.

---

## 4.17 11:00 — Continued Command-and-Control Communication

### Log Evidence

```text
11:00:05 onward
5156
Process: C:\ProgramData\svchost.exe
Destination: 194.34.132.15:4444
Approximately 56 connections
```

The same executable associated with the `SysUpdate` service repeatedly communicates with the same external endpoint.

The significance is derived from the complete process/network correlation rather than the destination port alone.

Port 4444 is not inherently malicious. In this context, however, the endpoint is contacted by a suspicious executable established through a suspicious service and encoded PowerShell execution.

**Assessment:** High-confidence malicious outbound communication consistent with command-and-control.

---

## 4.18 12:00 — Repeated Database Credential Modification

### Log Evidence

```text
12:00 - backup:
SELECT customers,
wp_users,
UPDATE user_pass
```

The same authentication-data modification pattern observed earlier reappears.

This provides additional evidence that modification of the WordPress credential datastore was not an isolated database operation.

**Assessment:** High-severity repeated modification of application authentication data.

---

## 4.19 13:00 — C2 Infrastructure Interacts With Web Shell

### Log Evidence

```text
13:00:00 - GET shell.php
13:00:01 - POST shell.php
13:00:02 - GET backup.tar.gz
```

The source associated with this activity is:

```text
194.34.132.15
```

The same address had previously been observed receiving outbound connections from:

```text
C:\ProgramData\svchost.exe
```

on the compromised Windows environment.

The external endpoint therefore appears in two distinct portions of the intrusion:

```text
Windows host
    ↓
C:\ProgramData\svchost.exe
    ↓
194.34.132.15:4444
```

and:

```text
194.34.132.15
    ↓
shell.php
    ↓
backup.tar.gz
```

This is a significant cross-host correlation linking the Windows-side malicious infrastructure with continued interaction against the compromised web application.

**Assessment:** High-confidence evidence of continued attacker interaction with WEB-01 and strong correlation with the identified external infrastructure.

---

## 4.20 17:00 — User Logoff Activity

### Log Evidence

```text
17:00 - Logoff events
```

The supplied evidence indicates user logoff activity.

A logoff event establishes termination of the associated authenticated session; it does not establish that all attacker persistence or malicious processes on the host have terminated.

No additional conclusion regarding attacker presence after logoff should therefore be derived from the logoff alone.

**Assessment:** Session termination observed; attacker presence after logoff cannot be determined from these events.

---

## 4.21 18:00 — Continued WordPress Activity

### Log Evidence

```text
18:00:00 - GET /wp-admin/
18:00:01 - POST /admin-ajax.php
18:00:02 - GET /backup.tar.gz
```

The sequence again demonstrates administrative WordPress access followed immediately by access to the backup archive.

The fact that this activity occurs after the 17:00 logoff does not, by itself, prove that an attacker used maryam's credentials.

Nevertheless, when correlated with the previously observed compromise, credential modification, web-shell activity, and archive access, the event represents a significant indicator of continued unauthorized access.

**Assessment:** High-priority suspicious activity; possible credential compromise or persistent attacker access.

---

## 4.22 20:00 — Malicious Activity Involving DC-01

### Log Evidence

```text
20:00:00 - 4624 Logon Type 10
User: maryam

20:00:01 - 4672
User: maryam

20:00:02 - 4688
Image: C:\Windows\System32\cmd.exe
Command: cmd.exe /c whoami

20:00:03 - 4688
Image: C:\Windows\System32\powershell.exe
Command: powershell.exe -Enc

20:00:04 - 7045
Service Name: SysUpdate
Image Path: C:\ProgramData\svchost.exe

20:00:05 onward - 5156
Process: C:\ProgramData\svchost.exe
Destination: 194.34.132.15:4444
```

This is one of the most significant evidence clusters in the incident.

The sequence reproduces the same malicious execution pattern previously observed on PC-MANAGER:

```text
Interactive logon
    ↓
Special privileges
    ↓
cmd.exe
    ↓
Encoded PowerShell
    ↓
SysUpdate service
    ↓
C:\ProgramData\svchost.exe
    ↓
194.34.132.15:4444
```

The repeated use of the same service name, executable path, and external destination provides strong evidence that the activity belongs to the same intrusion.

Because the affected asset is identified as DC-01, this event represents potential compromise of domain-level infrastructure.

There is, however, an important data-quality issue: the supplied logs associate 192.168.1.100 with both PC-MANAGER and DC-01. The host identity and IP mapping must therefore be validated before making definitive claims regarding lateral movement.

**Assessment:** High-confidence malicious activity involving DC-01; potential domain-level compromise.

---

## 4.23 22:00 — BACKUP-01 Activity

### Log Evidence

```text
22:00:00 - 4624 Logon Type 3
User: Veeam
Source IP: 172.16.10.50
Share: \BACKUP-01\Backup

22:00:01–22:00:25 - 5156
Process: C:\Program Files\Veeam\Backup.exe
Destination: 172.16.10.50:443
Protocol: TCP
Action: Allow
```

The observed activity involves the Veeam backup process, an internal source/destination relationship, and TCP/443 communication.

Nothing in the supplied events directly connects this activity to 45.33.22.11, 194.34.132.15, `shell.php`, `SysUpdate`, or the malicious PowerShell activity.

Accordingly, this event cannot currently be classified as part of the confirmed attack chain.

**Assessment:** No confirmed compromise. Activity appears consistent with legitimate backup operations, pending independent validation.

---

## 4.24 Consolidated Confirmed Attack Sequence

Based on the available evidence, the most defensible reconstruction is:


09:00
External authentication attack against WordPress
        │
        ▼
Repeated /wp-login.php POST requests
        │
        ▼
09:00:35
Access to /wp-admin/
        │
        ▼
09:00:37
Access to /backup.tar.gz
        │
        ▼
09:05
Successful SSH authentication as www-data
from 45.33.22.11
        │
        ▼
Host reconnaissance
        │
        ▼
Payload retrieval and execution
        │
        ▼
Security-control modification
        │
        ▼
sudoers modification
        │
        ▼
09:06
Web-shell interaction
        │
        ▼
Repeated backup archive access
        │
        ▼
09:30–09:35
Database authentication-data modification
        │
        ▼
09:40
Malicious activity on PC-MANAGER
        │
        ├── Encoded PowerShell
        ├── SysUpdate service
        └── C:\ProgramData\svchost.exe
                    │
                    ▼
             194.34.132.15:4444
                    │
                    ▼
11:00
Persistence/C2 activity repeated
                    │
                    ▼
12:00
Further database credential modification
                    │
                    ▼
13:00
External infrastructure accesses shell.php
and backup.tar.gz
                    │
                    ▼
18:00
Further WordPress administrative/archive activity
                    │
                    ▼
20:00
Same malicious execution pattern observed
on DC-01
                    │
                    ▼
Potential domain-level compromise

---

## 4.25 Timeline Conclusions

The confirmed evidence supports a multi-stage intrusion with persistence and continued access, rather than a single isolated attack.

The strongest confirmed progression is:

1. WordPress authentication attack
2. Successful access to administrative functionality
3. Server-side compromise of WEB-01
4. Payload execution and security-control modification
5. Persistence through sudoers
6. Web-shell deployment/interaction
7. Repeated access to a sensitive backup archive
8. Modification of WordPress authentication data
9. Malicious execution and persistence on a Windows endpoint
10. Repeated communication with 194.34.132.15:4444
11. Continued interaction with the compromised web server
12. Subsequent malicious activity involving DC-01

The timeline does not yet prove the exact mechanism used to move between WEB-01, DB-01, PC-MANAGER, and DC-01. It also does not conclusively establish that the 09:45 phishing email was the initial access vector, nor does it prove the exact volume of successfully exfiltrated data.

The most important unresolved transition remains:


WEB-01
   ↓
   [Lateral movement / credential compromise mechanism not directly observed]
   ↓
PC-MANAGER
   ↓
   [Further movement / credential abuse]
   ↓
DC-01

That gap should be treated as an investigative finding, not filled with assumptions. The next phase should therefore focus on reconstructing the lateral-movement path and determining how the attacker obtained the credentials associated with maryam, dbadmin, and www-data.
