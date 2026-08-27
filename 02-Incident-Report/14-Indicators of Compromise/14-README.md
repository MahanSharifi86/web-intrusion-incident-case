# 14. Indicators of Compromise

## 14.1 Purpose

This section consolidates the Indicators of Compromise (IOCs) identified during the investigation. Only artifacts directly observed in the supplied telemetry are included as confirmed indicators.

An IOC is not automatically proof of maliciousness in isolation. Each indicator is therefore accompanied by its observed context, affected asset, associated evidence, and confidence level.

The investigation identified indicators across network infrastructure, accounts, files, processes, services, URLs, and authentication activity.

---

## 14.2 Network Indicators

### 14.2.1 `45.33.22.11` — External Source IP

**Indicator:**

```text
45.33.22.11
```

**Observed in:**

```text
09:00:00 - GET /wp-login.php
09:00:01–09:00:34 - POST /wp-login.php
09:00:35 - GET /wp-admin/
09:05:00 - Accepted password for www-data from 45.33.22.11
```

**Affected asset:**

```text
WEB-01
```

**Assessment:**

The address is associated with repeated WordPress authentication attempts followed by successful administrative access and subsequent SSH authentication using www-data.

The temporal relationship between the web authentication activity and SSH access makes this one of the strongest external indicators in the case.

**Confidence:** High
**Classification:** Malicious / Compromised-source indicator

---

### 14.2.2 `194.34.132.15` — Suspected C2 Infrastructure

**Indicator:**

```text
194.34.132.15
```

**Observed in:**

```text
09:40:03 - C:\ProgramData\svchost.exe → 194.34.132.15:4444
```

Repeated firewall telemetry subsequently records connections to the same destination:

```text
Destination: 194.34.132.15:4444
Protocol: TCP
Action: Allow
```

The same destination is also associated with:

```text
13:00:00 - GET /shell.php
13:00:01 - POST /shell.php
13:00:02 - GET /backup.tar.gz
```

**Assessment:**

The address is strongly associated with the malicious service execution and subsequent web-shell interaction.

The available evidence supports classification as suspected C2 infrastructure. The exact C2 protocol is not established solely from the supplied firewall records.

**Confidence:** High
**Classification:** Suspected C2 infrastructure

---

### 14.2.3 TCP Port `4444`

**Indicator:**

```text
TCP/4444
```

**Observed in:**

```text
09:40:03 - svchost.exe → 194.34.132.15:4444
09:40:05 onward - repeated TCP connections
11:00:05 onward - repeated TCP connections
20:00:05 onward - repeated TCP connections
```

**Assessment:**

Port 4444 is not inherently malicious and should not be treated as an IOC independently.

Its significance derives from the combination of:

* suspicious executable path;
* newly created service;
* repeated outbound connections;
* external destination;
* temporal correlation with PowerShell execution.

**Confidence:** High when correlated with `194.34.132.15` and `C:\ProgramData\svchost.exe`.
**Classification:** Context-dependent network indicator

---

### 14.2.4 `10.10.10.200` — Brute-Force Source

**Indicator:**

```text
10.10.10.200
```

**Observed in:**

```text
08:30:00–08:30:20
Event ID: 4625
Logon Type: 3
User: Administrator
Source IP: 10.10.10.200
21 failed attempts
```

**Assessment:**

The activity is consistent with automated password-guessing against DC-01.

However, the source is an internal address and the available evidence does not establish that it belongs to an attacker-controlled host.

It should therefore be retained as an investigation indicator, not automatically classified as malicious.

If asset inventory identifies `10.10.10.200` as an authorized security scanner, this activity may represent a false positive.

**Confidence:** Medium
**Classification:** Suspicious / Requires attribution

---

## 14.3 Account Indicators

### 14.3.1 `www-data`

**Observed in:**

```text
09:05:00 - Accepted password for www-data from 45.33.22.11
```

Followed by:

```text
09:05:20 - bash /tmp/update.sh
09:05:30 - systemctl stop ufw
09:05:35 - chmod 777 /var/www/html -R
09:05:40 - modification of /etc/sudoers
```

**Assessment:**

The www-data account is directly associated with the post-compromise activity on WEB-01.

The evidence does not establish that the account itself was originally malicious; rather, it demonstrates that the legitimate service account was used during the compromise.

**Confidence:** High
**Classification:** Compromised account

---

### 14.3.2 `maryam`

**Observed in:**

```text
08:07:00 - 4624
Logon Type: 10
User: maryam
```

and subsequently:

```text
08:07:01 - 4672
User: maryam
```

Later activity includes:

```text
18:00:00 - GET /wp-admin/
18:00:01 - POST /admin-ajax.php
18:00:02 - repeated GET /backup.tar.gz
```

and:

```text
20:00:00 - 4624 Logon Type 10
User: maryam
20:00:01 - 4672
20:00:02 - cmd /c whoami
20:00:03 - PowerShell -Enc
20:00:04 - Service Created: SysUpdate
```

**Assessment:**

The account is strongly associated with suspicious activity.

However, the logs alone do not establish whether:

1. the legitimate user performed the activity;
2. the credentials were compromised;
3. the account was hijacked through an existing session; or
4. the source attribution is incomplete.

Therefore, maryam should be treated as a potentially compromised identity, rather than claiming that the user herself was the attacker.

**Confidence:** High for suspicious account activity; Medium for credential compromise.
**Classification:** Potentially compromised account

---

### 14.3.3 `dbadmin`

**Observed in:**

```text
09:35 - dbadmin
UPDATE wp_users
SET user_pass = MD5('newpassword')
```

**Assessment:**

The account performed a security-relevant modification to WordPress authentication data.

The evidence establishes the database modification but does not independently establish how dbadmin credentials were obtained.

**Confidence:** High
**Classification:** Suspicious privileged database account activity

---

## 14.4 File and Path Indicators

### 14.4.1 `/shell.php`

**Indicator:**

```text
/shell.php
```

**Observed in:**

```text
09:06:00 - GET /shell.php
09:06:01 - POST /shell.php
```

and:

```text
13:00:00 - GET /shell.php
13:00:01 - POST /shell.php
```

**Assessment:**

The repeated interactive access pattern is consistent with a server-side web shell.

The later association with `194.34.132.15` significantly strengthens the assessment.

**Confidence:** High
**Classification:** Malicious web-shell artifact

---

### 14.4.2 `/tmp/update.sh`

**Indicator:**

```text
/tmp/update.sh
```

**Observed in:**

```text
09:05:10 - wget update.sh
09:05:20 - bash /tmp/update.sh
```

**Assessment:**

A script was downloaded and subsequently executed from /tmp during the compromise.

The available telemetry does not contain the script's contents or cryptographic hash, so the file cannot be characterized beyond its observed role.

**Confidence:** High for suspicious execution; insufficient evidence for file-level malware classification.
**Classification:** Malicious-associated script

---

### 14.4.3 `C:\ProgramData\svchost.exe`

**Indicator:**

```text
C:\ProgramData\svchost.exe
```

**Observed in:**

```text
09:40:02 - Service Created: SysUpdate
Image Path: C:\ProgramData\svchost.exe
Start Type: Auto
```

followed by:

```text
09:40:03 - C:\ProgramData\svchost.exe
→ 194.34.132.15:4444
```

The same service/executable pattern is observed again at:

```text
11:00:04
20:00:04
```

**Assessment:**

This is one of the strongest host-based IOCs in the dataset.

The filename attempts to resemble the legitimate Windows svchost.exe, while the executable is located under `C:\ProgramData\` rather than the standard Windows system locations.

Combined with automatic service creation and external C2 communication, this strongly indicates a malicious persistence artifact.

**Confidence:** High
**Classification:** Malicious executable / persistence artifact

---

## 14.5 Persistence Indicators

### 14.5.1 `SysUpdate`

**Indicator:**

```text
Service Name: SysUpdate
```

**Observed in:**

```text
09:40:02 - Service Created: SysUpdate
Image Path: C:\ProgramData\svchost.exe
Start Type: Auto
```

Repeated:

```text
11:00:04 - Service Created: SysUpdate
20:00:04 - Service Created: SysUpdate
```

**Assessment:**

The service name, executable location, automatic startup configuration, and subsequent network communication form a coherent persistence indicator.

**Confidence:** High
**Classification:** Malicious persistence mechanism

---

### 14.5.2 `/etc/sudoers` Modification

**Indicator:**

```text
www-data ALL=(ALL) NOPASSWD: ALL
```

**Observed in:**

```text
09:05:40 - echo 'www-data ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
```

**Assessment:**

This modification grants www-data unrestricted passwordless sudo capability.

It is therefore both a persistence artifact and a privilege-escalation indicator.

**Confidence:** High
**Classification:** Malicious configuration modification

---

## 14.6 Web Indicators

### 14.6.1 `/wp-login.php`

**Indicator:**

```text
/wp-login.php
```

**Observed in:**

```text
09:00:00 - GET /wp-login.php
09:00:01–09:00:34 - 34 POST requests
```

**Assessment:**

The request sequence is consistent with automated credential guessing against WordPress authentication.

**Confidence:** High
**Classification:** Attack endpoint

---

### 14.6.2 `/wp-admin/`

**Indicator:**

```text
/wp-admin/
```

**Observed immediately after the authentication attempts:**

```text
09:00:35 - GET /wp-admin/
```

Additional activity appears later under the maryam identity.

The endpoint itself is legitimate WordPress functionality and is not malicious in isolation.

Its significance comes from its position in the attack sequence.

**Confidence:** High in attack-chain context
**Classification:** Compromise-associated endpoint

---

### 14.6.3 `/backup.tar.gz`

**Indicator:**

```text
/wp-content/uploads/2025/06/backup.tar.gz
```

**Observed repeatedly:**

```text
09:06:02–09:15:30 - approximately 110 requests
13:00:02 - approximately 49 requests
18:00:02 - approximately 100 requests
```

Each observed response reports:

```text
104857600 bytes
```

**Assessment:**

The archive is a high-value data-access indicator.

The logs support repeated retrieval of the archive but do not independently prove that every response completed successfully or establish the archive's contents.

**Confidence:** High for suspicious data access; Medium for confirmed exfiltration.
**Classification:** Sensitive-data access indicator

---

## 14.7 Process Indicators

### `powershell.exe -Enc`

**Observed in:**

```text
09:40:01 - powershell.exe -Enc
```

The encoded command contains a web-download operation.

Repeated at:

```text
11:00:03 - PowerShell -Enc
20:00:03 - PowerShell -Enc
```

**Assessment:**

Encoded PowerShell execution combined with subsequent service creation and C2 communication is a strong malicious execution indicator.

**Confidence:** High
**Classification:** Malicious-associated process execution

---

### `cmd.exe /c whoami`

**Observed in:**

```text
09:40:00 - cmd.exe /c whoami
11:00:02 - cmd /c whoami
20:00:02 - cmd /c whoami
```

**Assessment:**

The command itself is benign, but its repeated execution immediately before PowerShell and persistence activity makes it useful for behavioral correlation.

**Confidence:** High in contextual correlation
**Classification:** Behavioral indicator

---

## 14.8 Data-Access Indicators

The following artifact should be retained for investigation and detection purposes:

```text
backup.tar.gz
```

with the observed response size:

```text
104857600 bytes
```

and repeated access from external infrastructure.

A theoretical upper-bound based solely on the logged response sizes is:

```text
110 × 104857600 bytes
= 11,534,336,000 bytes
≈ 10.74 GiB
```

This figure should not be recorded as confirmed exfiltration volume. It represents the aggregate of reported HTTP response sizes under the assumption that all responses were fully transferred.

---

## 14.9 IOC Priority

| Priority | Indicator                          | Reason                                                                   |
| -------- | ---------------------------------- | ------------------------------------------------------------------------ |
| Critical | `194.34.132.15`                    | Associated with C2, web-shell access, and malicious service activity     |
| Critical | `C:\ProgramData\svchost.exe`       | Suspicious executable used by persistent service and C2                  |
| Critical | `SysUpdate`                        | Repeated malicious service persistence                                   |
| Critical | `/shell.php`                       | Web-shell activity                                                       |
| High     | `45.33.22.11`                      | WordPress brute force followed by SSH access                             |
| High     | `/backup.tar.gz`                   | Repeated access to large backup archive                                  |
| High     | `www-data`                         | Account directly used during WEB-01 compromise                           |
| High     | `www-data ALL=(ALL) NOPASSWD: ALL` | Privilege/persistence configuration change                               |
| High     | `PowerShell -Enc`                  | Encoded execution associated with persistence/C2                         |
| Medium   | `maryam`                           | Strongly suspicious identity activity; compromise attribution incomplete |
| Medium   | `dbadmin`                          | Security-relevant WordPress credential modification                      |
| Medium   | `10.10.10.200`                     | Brute-force source requiring asset attribution                           |
| Medium   | `TCP/4444`                         | Relevant only in correlation with the C2 destination/process             |

---

## 14.10 IOC Handling Notes

The following distinction should be preserved when this case is operationalized:

Do not block or classify every observed string independently.

For example:

```text
4444
```

is not inherently malicious.

Likewise:

```text
/wp-admin/
/wp-login.php
cmd.exe
powershell.exe
svchost.exe
maryam
```

are legitimate artifacts that become malicious or suspicious because of their surrounding behavioral context.

The highest-value detection logic should therefore correlate:

```text
Indicator
    +
Source / Destination
    +
Process
    +
Authentication
    +
Temporal sequence
```

The strongest IOC cluster identified in this investigation is:

```text
45.33.22.11
        ↓
WEB-01
        ↓
/wp-login.php
        ↓
/wp-admin/
        ↓
www-data SSH
        ↓
/tmp/update.sh
        ↓
/shell.php
        ↓
C:\ProgramData\svchost.exe
        ↓
SysUpdate
        ↓
194.34.132.15:4444
        ↓
backup.tar.gz
```

This cluster provides substantially stronger detection value than treating any individual IP, filename, port, or URL as malicious in isolation.
