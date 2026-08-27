# 13. MITRE ATT&CK Mapping

This section maps only behaviors supported by the available evidence to the MITRE ATT&CK framework. Techniques are classified according to the strength of the underlying evidence; behaviors that cannot be established from the logs are explicitly marked as not confirmed rather than being inferred as fact.

---

## 13.1 Technique Mapping Overview

| Tactic                                   | Technique                                   | ID        | Evidence                                                                  | Assessment                                                                     |
| ---------------------------------------- | ------------------------------------------- | --------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| Initial Access                           | Password Guessing                           | T1110.001 | 34 POST requests to `/wp-login.php` from `45.33.22.11`                    | Confirmed                                                                      |
| Initial Access                           | External Remote Services                    | T1133     | SSH access from `45.33.22.11`                                             | Confirmed, but access path requires validation                                 |
| Execution                                | PowerShell                                  | T1059.001 | `powershell.exe -Enc` on PC-MANAGER                                       | Confirmed                                                                      |
| Execution                                | Windows Command Shell                       | T1059.003 | `cmd.exe /c whoami`                                                       | Confirmed                                                                      |
| Execution                                | Unix Shell                                  | T1059.004 | `bash /tmp/update.sh`                                                     | Confirmed                                                                      |
| Persistence                              | Web Shell                                   | T1505.003 | `/shell.php` GET/POST activity                                            | Confirmed                                                                      |
| Persistence                              | Windows Service                             | T1543.003 | SysUpdate service creation                                                | Confirmed                                                                      |
| Persistence                              | Sudo and Sudo Caching                       | T1548.003 | `www-data ALL=(ALL) NOPASSWD: ALL` added to sudoers                       | Confirmed                                                                      |
| Privilege Escalation                     | Sudo and Sudo Caching                       | T1548.003 | Modification of `/etc/sudoers`                                            | Confirmed                                                                      |
| Discovery                                | System Owner/User Discovery                 | T1033     | `whoami`                                                                  | Confirmed                                                                      |
| Discovery                                | System Information Discovery                | T1082     | `hostname`                                                                | Confirmed                                                                      |
| Discovery                                | System Network Configuration Discovery      | T1016     | `ip a`                                                                    | Confirmed                                                                      |
| Defense Evasion                          | Impair Defenses                             | T1562.001 | `systemctl stop ufw`                                                      | Confirmed                                                                      |
| Defense Evasion                          | File and Directory Permissions Modification | T1222.002 | `chmod 777 /var/www/html -R`                                              | Confirmed                                                                      |
| Command and Control                      | Application Layer Protocol                  | T1071     | Repeated outbound TCP connection to `194.34.132.15:4444`                  | Partially supported                                                            |
| Command and Control                      | Non-Application Layer Protocol              | T1095     | Repeated TCP connection to `194.34.132.15:4444`                           | Possible, not confirmed                                                        |
| Lateral Movement                         | Remote Services                             | T1021     | Logon Type 10 activity involving PC-MANAGER/DC-01                         | Possible, requires correlation                                                 |
| Credential Access / Account Manipulation | Account Manipulation                        | T1098     | `UPDATE wp_users ... user_pass`                                           | Confirmed account modification; credential compromise not independently proven |
| Collection                               | Data from Local System                      | T1005     | Repeated retrieval of `backup.tar.gz`                                     | Possible                                                                       |
| Exfiltration                             | Exfiltration Over C2 Channel                | T1041     | External retrieval of backup data associated with attacker infrastructure | Potential; transfer completion requires validation                             |

---

## 13.2 Initial Access

### T1110.001 — Password Guessing

**Evidence:**

```text
09:00:00 - GET /wp-login.php
09:00:01–09:00:34 - POST /wp-login.php (34 attempts)
Source IP: 45.33.22.11
09:00:35 - GET /wp-admin/
```

The sequence demonstrates repeated authentication attempts against the WordPress login endpoint followed immediately by access to `/wp-admin/`.

The 34 POST requests within approximately 34 seconds constitute strong evidence of automated password-guessing activity. The subsequent administrative page request provides temporal evidence that authentication was likely successful.

**Assessment:** Confirmed.
**ATT&CK:** T1110.001 — Password Guessing.

---

## 13.3 External Remote Access

### T1133 — External Remote Services

**Evidence:**

```text
09:05:00 - Accepted password for www-data from 45.33.22.11
09:05:01 - session opened
```

The same external address associated with the preceding web attack subsequently authenticates through SSH using the `www-data` account.

This establishes external remote access to WEB-01. However, the logs do not independently establish how the `www-data` credentials were obtained.

**Assessment:** Confirmed external remote access; credential acquisition method remains undetermined.
**ATT&CK:** T1133 — External Remote Services.

---

## 13.4 Execution

### T1059.004 — Unix Shell

**Evidence:**

```text
09:05:20 - bash /tmp/update.sh
```

The attacker explicitly executes a downloaded shell script through Bash.

**Assessment:** Confirmed.

---

### T1059.001 — PowerShell

**Evidence:**

```text
09:40:01 - PowerShell -Enc
```

and:

```text
11:00:03 - PowerShell -Enc
20:00:03 - PowerShell -Enc
```

The use of `-Enc` indicates PowerShell's encoded-command mechanism. The supplied command data also contains an encoded invocation of a web client and download operation.

**Assessment:** Confirmed PowerShell execution.
**ATT&CK:** T1059.001 — PowerShell.

---

### T1059.003 — Windows Command Shell

**Evidence:**

```text
09:40:00 - cmd.exe /c whoami
11:00:02 - cmd /c whoami
20:00:02 - cmd /c whoami
```

The attacker repeatedly invokes Windows Command Shell before subsequent PowerShell and persistence activity.

**Assessment:** Confirmed.

---

## 13.5 Web Shell

### T1505.003 — Web Shell

**Evidence:**

```text
09:06:00 - GET /shell.php
09:06:01 - POST /shell.php
```

and later:

```text
13:00:00 - GET shell.php
13:00:01 - POST shell.php
```

The repeated GET/POST interaction with `shell.php` is consistent with an attacker-controlled server-side web shell.

The second occurrence is particularly significant because it occurs alongside subsequent retrieval of `backup.tar.gz`.

**Assessment:** Confirmed web-shell activity.
**ATT&CK:** T1505.003 — Web Shell.

---

## 13.6 Persistence and Privilege Escalation

### T1548.003 — Sudo and Sudo Caching

**Evidence:**

```text
09:05:40 - echo 'www-data ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
```

This modification grants the `www-data` account passwordless sudo privileges.

This is substantially more significant than simply observing administrative commands: the attacker modifies the authorization configuration so the compromised account can subsequently execute commands with elevated privileges.

**Assessment:** Confirmed persistence and privilege-escalation mechanism.
**ATT&CK:** T1548.003 — Sudo and Sudo Caching.

---

### T1543.003 — Windows Service

**Evidence:**

```text
09:40:02 - Service Created: SysUpdate
Image Path: C:\ProgramData\svchost.exe
Start Type: Auto
```

The attacker creates a service named SysUpdate configured for automatic startup.

The use of a system-like service name combined with an executable located under `C:\ProgramData\` is suspicious and consistent with persistence.

The same service-creation pattern subsequently appears at:

```text
11:00:04 - Service Created: SysUpdate
20:00:04 - Service Created: SysUpdate
```

**Assessment:** Confirmed malicious persistence mechanism.
**ATT&CK:** T1543.003 — Windows Service.

---

## 13.7 Discovery

### T1033 — System Owner/User Discovery

**Evidence:**

```text
09:05:05 - whoami
09:40:00 - cmd.exe /c whoami
11:00:02 - cmd /c whoami
20:00:02 - cmd /c whoami
```

`whoami` is repeatedly executed immediately after access, indicating identification of the current security context.

**Assessment:** Confirmed.

---

### T1082 — System Information Discovery

**Evidence:**

```text
09:05:05 - hostname
```

The attacker queries the hostname as part of initial post-compromise reconnaissance.

**Assessment:** Confirmed.

---

### T1016 — System Network Configuration Discovery

**Evidence:**

```text
09:05:05 - ip a
```

The attacker enumerates network configuration after gaining access to WEB-01.

**Assessment:** Confirmed.

---

## 13.8 Defense Evasion

### T1562.001 — Impair Defenses

**Evidence:**

```text
09:05:30 - systemctl stop ufw
```

The attacker explicitly disables the host firewall.

This is direct evidence of an attempt to impair a security control rather than merely an unusual administrative action.

**Assessment:** Confirmed.

---

### T1222.002 — File and Directory Permissions Modification

**Evidence:**

```text
09:05:35 - chmod 777 /var/www/html -R
```

The recursive modification grants broad read/write/execute permissions across the web root.

This materially weakens filesystem access controls and facilitates continued manipulation of web content.

**Assessment:** Confirmed.

---

## 13.9 Command and Control

### T1071 / T1095 — Application or Non-Application Layer C2

**Evidence:**

```text
09:40:03 - svchost.exe → 194.34.132.15:4444
```

followed by repeated connections:

```text
09:40:05–09:40:... - 5156
Destination: 194.34.132.15:4444
Protocol: TCP
Action: Allow
```

and:

```text
11:00:05 onward - 5156
Destination: 194.34.132.15:4444
```

The repeated outbound connections originate from the suspicious SysUpdate service executable and target the same external address.

This provides strong evidence of command-and-control communication.

However, the logs identify only TCP and port 4444; they do not identify the actual application-layer protocol. Therefore, assigning a specific protocol such as HTTP, HTTPS, or DNS would be unsupported.

**Assessment:** C2 activity strongly supported. Exact ATT&CK protocol classification remains unresolved.

**ATT&CK:** T1095 is a reasonable provisional mapping if the traffic is confirmed to be a custom/non-application protocol. T1071 should not be asserted without protocol-level evidence.

---

## 13.10 Lateral Movement

### T1021 — Remote Services

**Evidence:**

```text
08:07:00 - 4624 Logon Type 10
User: maryam
Source IP: 192.168.1.100
```

Later:

```text
20:00:00 - 4624 Logon Type 10
User: maryam
Source IP: 192.168.1.100
```

The presence of Logon Type 10 is consistent with a Remote Interactive logon, commonly associated with RDP.

However, the supplied dataset contains an important attribution problem: `192.168.1.100` is also used as the apparent host address for PC-MANAGER and is presented in the DC-01 record.

Therefore, the logs currently demonstrate remote-interactive authentication, but they do not provide sufficient network correlation to prove the complete movement path:

```text
WEB-01 → PC-MANAGER → DC-01
```

**Assessment:** Lateral movement is a strong hypothesis, but the exact movement path should remain unconfirmed until source/destination addressing and RDP/Terminal Services logs are correlated.

**ATT&CK:** T1021.001 — Remote Services: RDP, if RDP-specific evidence is subsequently confirmed.

---

## 13.11 Account Manipulation

### T1098 — Account Manipulation

**Evidence:**

```text
09:35 - dbadmin:
UPDATE wp_users
SET user_pass = MD5('newpassword')
```

and:

```text
12:00 - backup:
SELECT customers, wp_users, UPDATE user_pass
```

The database activity includes modification of WordPress user credentials.

This establishes unauthorized or at least security-relevant account modification in the context of the surrounding attack chain. It does not, by itself, prove that the attacker successfully obtained the new credential or authenticated using it.

**Assessment:** Account manipulation confirmed; subsequent credential use requires separate evidence.
**ATT&CK:** T1098 — Account Manipulation.

---

## 13.12 Data Access and Potential Exfiltration

### T1005 — Data from Local System

**Evidence:**

```text
09:06:02–09:15:30 - GET /backup.tar.gz
Approximately 110 requests
Response size: 104857600 bytes per request
```

Additional activity:

```text
13:00:02 - GET backup.tar.gz
49 requests
```

and:

```text
18:00:02 - GET backup.tar.gz
100 requests
```

The repeated retrieval of a 100 MiB backup archive demonstrates access to a large local data object hosted by WEB-01.

The archive is explicitly named `backup.tar.gz`, but its contents are not present in the supplied evidence. Therefore, the report should not claim that the archive contained customer records, credentials, source code, or other specific information without additional evidence.

**Assessment:** Data access strongly supported.

---

### T1041 — Exfiltration Over C2 Channel

The external retrieval of `backup.tar.gz` is consistent with possible data exfiltration.

However, HTTP access logs establish requests and response sizes, not necessarily successful end-to-end transfer of every byte. A 100 MiB response size repeated approximately 110 times would theoretically represent:

```text
100 MiB × 110 = 11,000 MiB
≈ 10.74 GiB
```

But this should be described as potential transferred volume, not confirmed exfiltrated data, until network-flow, HTTP completion, or equivalent evidence confirms successful transfers.

**Assessment:** Potential exfiltration; not fully confirmed from the supplied web logs alone.
**ATT&CK:** T1041 — Exfiltration Over C2 Channel is a plausible mapping if the external retrieval is demonstrated to use the attacker's C2 infrastructure.

---

## 13.13 Techniques Explicitly Not Confirmed

Several techniques might appear attractive during analysis but should not be asserted solely from the supplied evidence.

### T1566 — Phishing

**Evidence:**

```text
09:45:03–09:45:07
From: 194.34.132.15
Attachment: invoice_pdf.exe
```

The email is suspicious and potentially malicious, but it occurs after the 09:40 compromise sequence.

Therefore, it cannot currently be identified as the initial-access mechanism for PC-MANAGER.

**Assessment:** Suspicious artifact; phishing as the initial-access technique is not confirmed.

---

### T1213 — Data from Information Repositories

This technique should not be used for the `backup.tar.gz` downloads.

The evidence concerns retrieval of an archive from a web server, not access to SharePoint, OneDrive, or another repository covered by T1213.

**Assessment:** Not applicable based on current evidence.

---

## 13.14 ATT&CK Interpretation of the Attack

The strongest ATT&CK-supported chain currently established from the evidence is:

```text
T1110.001
Password Guessing
        |
        v
T1133
External Remote Services
        |
        v
T1059.*
Command/Scripting Interpreter
        |
        +---- T1033  User Discovery
        +---- T1082  System Information Discovery
        +---- T1016  Network Configuration Discovery
        |
        v
T1505.003
Web Shell
        |
        +---- T1562.001  Impair Defenses
        +---- T1222.002  File/Directory Permissions Modification
        +---- T1548.003  Sudo Configuration
        |
        v
T1543.003
Windows Service Persistence
        |
        v
C2 Activity
194.34.132.15:4444
        |
        v
Potential T1021.001
Lateral Movement
        |
        v
T1098
Account Manipulation
        |
        v
T1005
Data Access
        |
        v
Potential T1041
Exfiltration
```

The important distinction is that the ATT&CK mapping does not itself prove the attack chain. It provides a standardized representation of behaviors already supported by evidence.

The highest-confidence techniques in this case are T1110.001, T1059.001, T1059.003, T1505.003, T1543.003, T1548.003, T1562.001, T1222.002, T1033, T1082, and T1016.

The weaker portions of the chain are specifically the exact lateral-movement path, the mechanism by which credentials were obtained, the exact C2 protocol, and whether all backup downloads completed successfully. Those should remain investigation items rather than being promoted to confirmed findings.
