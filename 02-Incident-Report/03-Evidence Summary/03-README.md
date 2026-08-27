# 3. Evidence Summary

## 3.1 Evidence Overview

The investigation is based on correlated application, authentication, process execution, service creation, network connection, database, and web-server telemetry collected from the affected environment.

The evidence demonstrates a progression from unauthorized access to web infrastructure, through post-compromise execution and persistence, followed by web-shell activity, credential manipulation, command-and-control communication, and activity involving higher-value internal systems.

The evidence does not, however, establish every element of the intrusion with equal confidence. The distinction between directly observed facts and investigative assessments is therefore maintained throughout this report.

---

## 3.2 Initial Web Authentication and Archive Access

### Relevant log evidence

```text
09:00:00 - GET /wp-login.php
09:00:01–09:00:34 - POST /wp-login.php (34 attempts)
09:00:35 - GET /wp-admin/
09:00:36 - POST /admin-ajax.php
09:00:37 - GET /backup.tar.gz
````

The sequence begins with repeated POST requests against `/wp-login.php`, followed immediately by successful access to `/wp-admin/`.

The transition from repeated authentication attempts to authenticated administrative functionality is a significant indicator of successful credential-based access.

The subsequent request for:

```text
/backup.tar.gz
```

is particularly significant because the requested object is a backup archive located under the web application's content path.

**Assessment:** High-confidence evidence of unauthorized authentication activity followed by access to a potentially sensitive backup artifact.

---

## 3.3 Successful SSH Authentication to WEB-01

### Relevant log evidence

```text
09:05:00 - Accepted password for www-data from 45.33.22.11
09:05:01 - session opened
```

The same external address previously associated with the web attack is observed immediately before successful SSH authentication as `www-data`.

The temporal relationship between the web compromise and SSH authentication materially strengthens the correlation between the two events.

The account name `www-data` does not by itself demonstrate root-level access.

**Assessment:** High-confidence evidence that the attacker obtained valid credentials or another mechanism permitting SSH authentication as `www-data`.

---

## 3.4 Post-Authentication Host Discovery

### Relevant log evidence

```text
09:05:05 - whoami && hostname && ip a
```

These commands enumerate the current security context, hostname, and network configuration.

This activity is characteristic of post-compromise host discovery because it provides the operator with information necessary to understand the compromised environment before continuing the intrusion.

**Assessment:** Strong evidence of deliberate post-compromise reconnaissance.

---

## 3.5 Payload Retrieval and Execution

### Relevant log evidence

```text
09:05:10 - wget update.sh
09:05:15 - downloading secondary payload
09:05:20 - bash /tmp/update.sh
```

The sequence demonstrates retrieval of an externally supplied script followed by execution from `/tmp`.

The evidence does not expose the contents or cryptographic identity of `update.sh`, so the exact payload functionality cannot be established from these logs alone.

However, its placement within an already established compromise sequence makes benign administrative activity unlikely.

**Assessment:** High-confidence evidence of malicious payload delivery and execution.

---

## 3.6 Security-Control Modification and Persistence on WEB-01

### Relevant log evidence

```text
09:05:25 - systemctl stop nginx
09:05:30 - systemctl stop ufw
09:05:35 - chmod 777 /var/www/html -R
09:05:40 - echo 'www-data ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
```

These events represent a substantial escalation in attacker capability.

Stopping nginx disrupts the web service, while stopping ufw removes a host-based network control.

The recursive:

```text
chmod 777 /var/www/html -R
```

weakens filesystem permissions across the web root.

Most significantly, modifying `/etc/sudoers` to grant:

```text
www-data ALL=(ALL) NOPASSWD: ALL
```

would provide the `www-data` account unrestricted passwordless sudo capability if the modification was successfully applied.

This is a persistence and privilege-escalation mechanism rather than merely routine application administration.

**Assessment:** High-confidence evidence of deliberate compromise, security-control degradation, and establishment of persistent elevated access.

---

## 3.7 Web-Shell Activity

### Relevant log evidence

```text
09:06:00 - GET /shell.php
09:06:01 - POST /shell.php
```

The presence of both GET and POST requests to `shell.php` immediately following payload execution is highly significant.

A filename alone is insufficient to prove that a file is a web shell. However, when correlated with the preceding unauthorized access, payload execution, and subsequent POST interaction, the evidence strongly supports the assessment that `shell.php` functioned as an attacker-controlled web interface.

**Assessment:** High-confidence evidence of web-shell interaction; confirmation of its exact implementation requires filesystem or application evidence.

---

## 3.8 Repeated Access to backup.tar.gz

### Relevant log evidence

```text
09:06:02–09:15:30 - GET /backup.tar.gz
Approximately 110 requests
```

Earlier and later requests establish that the same archive was repeatedly accessed during the intrusion.

The supplied logs indicate an individual response size of:

```text
104857600 bytes
```

which corresponds to 100 MiB per logged response.

If all approximately 110 responses represent complete successful transfers, the theoretical transferred volume would be approximately:

```text
11,534,336,000 bytes
≈ 10.74 GiB
```

However, HTTP access logs alone do not prove that every response was fully received by the external party. Retransmissions, partial responses, interrupted connections, caching behavior, or other factors could alter the actual transferred volume.

Therefore, the evidence establishes repeated access to a sensitive archive, but the exact amount of successfully exfiltrated data requires corroboration from network-flow, proxy, packet, or endpoint telemetry.

**Assessment:** High-confidence evidence of repeated unauthorized access to a potentially sensitive backup archive; confirmed exfiltration volume remains unproven.

---

## 3.9 Credential and Database Activity

### Relevant log evidence

```text
09:30 - backup: SELECT customers, orders
09:35 - dbadmin: SELECT wp_users, UPDATE user_pass
```

The backup account's read operations are consistent with legitimate backup behavior and are not independently suspicious.

The subsequent `dbadmin` activity is materially different because it includes modification of the WordPress authentication data.

The supplied evidence indicates an operation against `wp_users` involving `user_pass`.

This creates a direct integrity concern for the application's authentication system and could permit an attacker to establish or alter credentials.

**Assessment:** High-severity evidence of unauthorized modification to application authentication data, although the mechanism by which `dbadmin` access was obtained is not established by these logs alone.

---

## 3.10 PowerShell, Service Creation, and C2 Activity

### Relevant log evidence

```text
09:40:00 - cmd.exe /c whoami
09:40:01 - PowerShell -Enc
09:40:02 - Service Created: SysUpdate
              Image Path: C:\ProgramData\svchost.exe
09:40:03 - svchost.exe → 194.34.132.15:4444
```

This sequence is one of the strongest evidence clusters in the investigation.

The encoded PowerShell command indicates execution of obfuscated command content. The subsequent creation of `SysUpdate` establishes a new Windows service using an executable located at:

```text
C:\ProgramData\svchost.exe
```

The filename resembles a legitimate Windows process, while its location outside the standard Windows system directory warrants investigation.

Immediately afterward, the same process communicates with:

```text
194.34.132.15:4444
```

The combination of encoded PowerShell, suspicious service creation, unusual executable location, and outbound communication to an external host strongly supports a malicious persistence and command-and-control assessment.

**Assessment:** High-confidence evidence of malware execution, persistence, and external command-and-control activity.

---

## 3.11 Repeated C2 Communication

### Relevant log evidence

```text
09:40:03 onward
Process: C:\ProgramData\svchost.exe
Destination: 194.34.132.15:4444
Protocol: TCP
Action: Allow
```

The connection is not an isolated network event. The supplied telemetry shows repeated connections from the suspicious executable to the same external endpoint.

The same infrastructure is subsequently observed during later malicious activity.

Port `4444` should not independently be treated as proof of command-and-control. The significance comes from the process-to-network correlation:

```text
Suspicious executable
        ↓
C:\ProgramData\svchost.exe
        ↓
External destination
        ↓
194.34.132.15:4444
```

**Assessment:** High-confidence malicious network activity associated with the suspicious process; C2 classification is strongly supported by the surrounding evidence.

---

## 3.12 Repeated Malicious Execution on DC-01

### Relevant log evidence

```text
20:00:00 - 4624 Logon Type 10
User: maryam

20:00:01 - 4672 Special Privileges
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

This event sequence reproduces the same behavioral pattern previously observed on PC-MANAGER.

The combination of remote interactive authentication, privileged access, process creation, encoded PowerShell, service creation, and communication with the previously identified external endpoint provides strong evidence that the activity is part of the same intrusion.

Because the affected asset is identified as DC-01, this evidence materially raises the potential severity of the incident.

**Assessment:** High-confidence evidence of malicious activity on a Domain Controller and potential domain-level compromise.

---

## 3.13 Repeated Web-Shell Access from External Infrastructure

### Relevant log evidence

```text
13:00:00 - GET shell.php
13:00:01 - POST shell.php
13:00:02 - GET backup.tar.gz
```

The source associated with these requests is identified in the supplied scenario as:

```text
194.34.132.15
```

The endpoint previously appears in C2 communication from the suspicious Windows process.

The correlation between the external endpoint, web-shell interaction, and subsequent archive access provides a strong relationship between the web-facing compromise and the Windows-side C2 infrastructure.

**Assessment:** High-confidence evidence linking the identified external infrastructure to continued interaction with the compromised web application.

---

## 3.14 Post-Logoff Activity Associated with maryam

### Relevant log evidence

```text
18:00:00 - GET /wp-admin/
18:00:01 - POST /admin-ajax.php
18:00:02 - GET /backup.tar.gz
```

The activity occurs after the earlier user logoff period and reproduces the previously observed administrative-access and archive-access pattern.

The logs demonstrate activity under the `maryam` identity, but they do not by themselves establish whether the legitimate user or an attacker possessing her credentials performed the actions.

This distinction is important: an account name in an application log identifies the authenticated identity, not necessarily the human operator.

**Assessment:** Suspicious activity requiring credential-compromise investigation; attribution to the legitimate user cannot be established from the supplied logs alone.

---

## 3.15 Phishing Evidence

### Relevant log evidence

```text
09:45:03–09:45:07
From: 194.34.132.15
Attachment: invoice_pdf.exe
```

The executable attachment is consistent with a phishing delivery mechanism.

However, the timestamp occurs after malicious activity had already been established on PC-MANAGER at approximately 09:40.

Consequently, this evidence cannot currently establish phishing as the initial access vector.

It may instead represent:

* a secondary delivery attempt;
* an additional stage of the intrusion;
* a separate malicious campaign;
* or evidence of an earlier phishing event for which telemetry is unavailable.

**Assessment:** High-value supporting evidence of malicious delivery infrastructure, but low confidence as the initial access mechanism.

---

## 3.16 Backup Infrastructure Activity

### Relevant log evidence

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

The process path, service account, internal source, internal destination, and HTTPS communication are consistent with expected backup operations.

No supplied event connects this activity to the malicious external infrastructure or to the confirmed compromise indicators.

Therefore, the evidence does not currently support classifying BACKUP-01 as compromised.

**Assessment:** Currently assessed as benign/expected activity pending corroboration.

---

## 3.17 Evidence Correlation

The strongest relationships identified in the evidence are:

```text
45.33.22.11
      │
      ├── Repeated /wp-login.php attempts
      │
      ├── Successful /wp-admin/ access
      │
      └── Successful SSH authentication as www-data
                    │
                    ▼
                 WEB-01
                    │
                    ├── Host discovery
                    ├── Payload retrieval
                    ├── Payload execution
                    ├── Security-control modification
                    ├── sudoers modification
                    └── shell.php
                              │
                              ▼
                     backup.tar.gz access
                              │
                              ▼
                    Database credential modification
                              │
                              ▼
                       Windows-side activity
                              │
                              ├── Encoded PowerShell
                              ├── SysUpdate service
                              └── C:\ProgramData\svchost.exe
                                         │
                                         ▼
                              194.34.132.15:4444
                                         │
                                         ▼
                              Continued web-shell access
                                         │
                                         ▼
                              Activity involving DC-01
```

This correlation represents the principal investigative hypothesis supported by the available telemetry. The exact transition between individual hosts remains an area requiring additional evidence.

---

## 3.18 Evidence Gaps

Several important questions cannot be resolved from the supplied logs alone:

### 1. Initial Access Vector

The evidence establishes successful compromise but does not conclusively identify whether the first access resulted from credential compromise, exploitation, phishing, or another mechanism.

### 2. Lateral Movement Path

The exact mechanism connecting WEB-01, PC-MANAGER, DB-01, and DC-01 is not directly recorded.

### 3. Credential Compromise

The logs demonstrate use of `maryam`, `www-data`, and `dbadmin`, but do not establish when or how their credentials were obtained.

### 4. Exfiltration Confirmation

Repeated GET requests and response sizes indicate substantial archive access, but network telemetry is required to confirm the amount actually transferred externally.

### 5. DC-01 Identity/IP Inconsistency

The supplied dataset associates `192.168.1.100` with both PC-MANAGER and DC-01. Host inventory, DHCP, EDR, or authentication telemetry is required to resolve this discrepancy.

### 6. Payload Identification

The contents and hashes of `update.sh`, `C:\ProgramData\svchost.exe`, and `shell.php` are not provided.

### 7. Phishing Timeline

The 09:45 malicious email cannot currently be linked to the initial compromise.

---

## 3.19 Evidence Assessment

The available evidence is sufficient to establish a coherent multi-stage intrusion with high confidence.

The most significant evidence is not any individual log entry, but the repeated correlation of:

* unauthorized authentication;
* post-authentication reconnaissance;
* payload execution;
* persistence;
* security-control modification;
* web-shell interaction;
* sensitive archive access;
* credential/database modification;
* suspicious PowerShell execution;
* malicious service creation; and
* repeated communication with the same external infrastructure.

The investigation should therefore proceed on the basis that WEB-01 and PC-MANAGER are compromised, DC-01 is highly likely compromised, DB-01 has suffered an authentication-data integrity impact, and the status of BACKUP-01 remains unconfirmed.

The principal unresolved investigative questions are the true initial access vector, lateral movement mechanism, credential compromise path, and confirmed quantity of data exfiltrated.

```
```
