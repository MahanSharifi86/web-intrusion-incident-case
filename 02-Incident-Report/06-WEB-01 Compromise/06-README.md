# 6. WEB-01 Compromise

## 6.1 Overview

WEB-01 represents the first asset for which the supplied evidence establishes a high-confidence malicious compromise.

The available telemetry shows a progression from repeated authentication activity against the WordPress administrative interface to authenticated application access, subsequent SSH access using the `www-data` account, host reconnaissance, payload retrieval and execution, security-control modification, privilege configuration changes, and deployment of a web shell.

The evidence supports a coherent compromise chain:

```text
External Access
    ↓
WordPress Authentication Abuse
    ↓
Authenticated WordPress Access
    ↓
Sensitive File Access
    ↓
SSH Access as www-data
    ↓
Host Reconnaissance
    ↓
Payload Retrieval
    ↓
Payload Execution
    ↓
Security Control Modification
    ↓
Privilege Configuration Change
    ↓
Web Shell Deployment
```

The compromise of WEB-01 is therefore assessed as confirmed.

---

## 6.2 WordPress Authentication Abuse

### Evidence

```text
09:00:00 - GET /wp-login.php
09:00:01–09:00:34 - POST /wp-login.php (34 attempts)
```

The attacker repeatedly submitted authentication requests to the WordPress login endpoint within approximately 34 seconds.

The concentration of authentication attempts against `/wp-login.php` is inconsistent with normal user interaction and is characteristic of automated credential-guessing activity.

### Assessment

This is assessed as malicious authentication activity with high confidence.

The available evidence does not expose the submitted credentials or individual authentication responses, so the logs alone do not prove that every POST represented a failed authentication attempt.

However, the subsequent access to the administrative interface provides strong evidence that the attacker obtained authenticated access.

---

## 6.3 Transition to Authenticated WordPress Access

### Evidence

```text
09:00:35 - GET /wp-admin/
09:00:36 - POST /admin-ajax.php
```

The administrative interface was accessed immediately after the authentication sequence.

The following request to:

```text
/wp-admin/admin-ajax.php
```

further demonstrates interaction with authenticated WordPress functionality.

### Assessment

The temporal relationship is significant:

```text
34 authentication attempts
        ↓
/wp-admin/
        ↓
admin-ajax.php
```

This strongly indicates that the authentication activity resulted in, or was followed by, valid application access.

The exact WordPress account used for this session is not identified in the supplied HTTP logs. Consequently, the report should not attribute the successful session to maryam or another specific account without additional authentication telemetry.

---

## 6.4 Access to Exposed Backup Archive

### Evidence

```text
09:00:37 - GET /backup.tar.gz
```

The attacker requested a backup archive immediately after gaining access to the WordPress administrative area.

The archive is later observed repeatedly in the attack chain.

### Assessment

The filename `backup.tar.gz` indicates potentially sensitive stored data. A backup archive may contain application source code, configuration files, database exports, credentials, secrets, or other internal information depending on its contents.

The HTTP response status and size associated with the later repeated requests are:

```text
200 104857600
```

indicating successful HTTP responses of 100 MiB per request.

The request itself establishes access to the archive, but does not by itself prove that its contents were successfully exfiltrated outside the environment. That distinction becomes important when evaluating the later repeated downloads.

---

## 6.5 SSH Access to WEB-01

### Evidence

```text
09:05:00 - Accepted password for www-data from 45.33.22.11
09:05:01 - session opened
```

Five minutes after the WordPress activity, the same external IP address:

```text
45.33.22.11
```

successfully authenticated to WEB-01 using:

```text
www-data
```

### Assessment

This provides a second, independent access channel associated with the same external source.

The `www-data` account is commonly associated with web-server processes on Linux systems. Interactive SSH access using this account is therefore particularly significant and requires investigation into why the account possessed an SSH-capable password and whether such access was authorized.

The evidence confirms successful SSH access, but does not establish how the attacker obtained the `www-data` credentials.

Therefore:

* **Confirmed:** attacker-controlled access to WEB-01 through SSH.
* **Not confirmed:** the mechanism by which the `www-data` credentials were obtained.

---

## 6.6 Post-Compromise Host Reconnaissance

### Evidence

```text
09:05:05 - whoami && hostname && ip a
```

The attacker immediately executed commands designed to establish:

* the current security context (`whoami`);
* the compromised host identity (`hostname`);
* network configuration and interfaces (`ip a`).

### Assessment

This represents post-compromise reconnaissance.

The sequence is consistent with an operator determining:

1. Which account they currently control.
2. Which system they have compromised.
3. What network interfaces and addresses are available.
4. Whether the system provides access to additional network segments.

This is materially different from routine application administration because the commands occur immediately after external SSH authentication and are followed by payload deployment.

---

## 6.7 Payload Retrieval and Execution

### Evidence

```text
09:05:10 - wget update.sh
09:05:15 - downloading secondary payload
09:05:20 - bash /tmp/update.sh
```

The attacker retrieved a shell script and subsequently executed it from `/tmp`.

The sequence is:

```text
wget update.sh
      ↓
Secondary payload download
      ↓
bash /tmp/update.sh
```

### Assessment

This is high-confidence malicious execution.

The timing, external origin, interactive reconnaissance, payload retrieval, and immediate execution form a coherent post-compromise execution chain.

The supplied logs do not provide the contents or cryptographic hash of `update.sh`, so the exact functionality of the script cannot be independently established from these events alone.

Nevertheless, its role in the attack chain is strongly supported by the subsequent system modifications.

---

## 6.8 Security Control Modification

### Evidence

```text
09:05:25 - systemctl stop nginx
09:05:30 - systemctl stop ufw
```

The attacker stopped both:

```text
nginx
ufw
```

### Assessment

This represents a significant change in the security posture of WEB-01.

Stopping Nginx disrupts the legitimate web service, while stopping UFW removes a host-level network filtering control.

The combination is particularly significant because it occurs immediately after malicious payload execution.

This behavior is consistent with an attacker attempting to:

* disrupt defensive controls;
* modify the exposed application;
* prevent interference with malicious activity;
* or prepare the host for additional operations.

The evidence confirms that the commands were executed; the precise operational purpose cannot be determined solely from these two events.

---

## 6.9 Permission Weakening

### Evidence

```text
09:05:35 - chmod 777 /var/www/html -R
```

The attacker recursively changed permissions on the web root to:

```text
777
```

### Assessment

This is a significant security-control degradation.

Recursive `777` permissions grant read, write, and execute permissions to the owner, group, and other users for affected filesystem objects, subject to the exact behavior and object types involved.

Applied to the web root, this substantially weakens filesystem access controls and can facilitate modification of application files by unauthorized processes or accounts.

The timing is also important:

```text
Payload execution
      ↓
Nginx stopped
      ↓
UFW stopped
      ↓
Web-root permissions weakened
```

This provides strong evidence that the attacker was actively modifying the host rather than merely inspecting it.

---

## 6.10 Privilege Persistence Through sudoers

### Evidence

```text
09:05:40 - echo 'www-data ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
```

The attacker modified `/etc/sudoers` to grant:

```text
www-data ALL=(ALL) NOPASSWD: ALL
```

### Assessment

This is one of the strongest indicators of deliberate persistence and privilege expansion in the WEB-01 compromise.

The modification grants the `www-data` account unrestricted sudo capability without requiring a password.

Consequently, an attacker retaining access to the `www-data` account could potentially execute commands with root privileges through sudo.

This is more accurately described as privilege configuration modification with persistence implications, rather than simply stating that the attacker "became root."

The supplied evidence does not contain a subsequent sudo or root execution event.

Therefore:

The attacker established a configuration that would allow `www-data` to obtain root-level execution, but the supplied evidence does not independently prove that root privileges were subsequently exercised.

---

## 6.11 Web Shell Deployment

### Evidence

```text
09:06:00 - GET /shell.php
09:06:01 - POST /shell.php
```

Immediately following the host-level modifications, the web application exposes a file named:

```text
/shell.php
```

which receives both GET and POST requests.

### Assessment

The sequence is highly consistent with deployment and subsequent interaction with a PHP web shell.

The surrounding evidence substantially increases confidence:

```text
SSH access
   ↓
Reconnaissance
   ↓
Payload execution
   ↓
Nginx/UFW modification
   ↓
Web-root permission modification
   ↓
/shell.php
```

The supplied logs do not contain the file creation event itself, so the exact mechanism by which `shell.php` was written is not directly observed.

Nevertheless, its appearance immediately after the compromise and subsequent attacker interaction makes malicious web-shell functionality highly likely.

For a formal incident report, the strongest defensible wording is:

> A PHP resource named shell.php was accessed immediately following confirmed host compromise and privilege/security-control modifications. The available evidence is strongly indicative of a deployed web shell, although the file-creation event itself is not present in the supplied telemetry.

---

## 6.12 Repeated Access to backup.tar.gz

### Evidence

```text
09:06:02–09:15:30
GET /backup.tar.gz
Approximately 110 requests
```

Each corresponding HTTP response is recorded as:

```text
200 104857600
```

The response size is:

```text
104,857,600 bytes
```

or exactly 100 MiB per response.

If every response represents a complete successful transfer, the theoretical transferred volume would be approximately:

```text
110 × 100 MiB
= 11,000 MiB
≈ 10.74 GiB
```

### Assessment

The volume and repetition are highly anomalous and strongly associated with the compromised web application.

However, a senior-level assessment must distinguish HTTP response volume from confirmed external data exfiltration.

The logs demonstrate:

* repeated requests;
* successful HTTP responses;
* a large response size;
* access through a compromised server;
* activity following web-shell deployment.

They do not independently establish that all 110 responses were completely received by an external attacker.

Therefore, the correct assessment is:

> The evidence demonstrates large-scale repeated access to a sensitive backup archive and provides strong evidence of attempted or probable data transfer. Confirmed data exfiltration requires corroboration from network-flow, proxy, packet, or endpoint telemetry.

---

## 6.13 WEB-01 Attack Chain Reconstruction

Based exclusively on the supplied evidence, the most defensible reconstruction is:

```text
09:00:00
External source 45.33.22.11
        │
        ▼
WordPress authentication abuse
/wp-login.php
        │
        ▼
09:00:35
/wp-admin/ accessed
        │
        ▼
09:00:36
/admin-ajax.php
        │
        ▼
09:00:37
/backup.tar.gz accessed
        │
        ▼
09:05:00
SSH authentication as www-data
        │
        ▼
09:05:05
Host reconnaissance
whoami / hostname / ip a
        │
        ▼
09:05:10–09:05:20
Payload retrieval and execution
wget → update.sh → bash
        │
        ▼
09:05:25–09:05:30
Security controls modified
Nginx stopped
UFW stopped
        │
        ▼
09:05:35
Web-root permissions weakened
chmod 777
        │
        ▼
09:05:40
Sudoers modified
www-data → unrestricted NOPASSWD sudo
        │
        ▼
09:06:00
shell.php accessed
        │
        ▼
09:06:02–09:15:30
Repeated backup archive access
```

This sequence represents a coherent compromise rather than a collection of unrelated suspicious events.

---

## 6.14 Confidence Assessment

| Finding                                       | Confidence                    | Basis                                                                        |
| --------------------------------------------- | ----------------------------- | ---------------------------------------------------------------------------- |
| WEB-01 was compromised                        | High                          | Multiple independent malicious activities                                    |
| 45.33.22.11 is associated with the compromise | High                          | WordPress activity followed by SSH authentication from same source           |
| WordPress authentication was abused           | High                          | 34 authentication requests followed by administrative access                 |
| Valid WordPress authentication was obtained   | High                          | `/wp-admin/` and `admin-ajax.php` immediately follow authentication activity |
| SSH access using www-data occurred            | High                          | Successful SSH authentication event                                          |
| Host reconnaissance occurred                  | High                          | `whoami`, `hostname`, `ip a`                                                 |
| Malicious payload was executed                | High                          | Download followed by `bash /tmp/update.sh`                                   |
| Defensive controls were disabled              | High                          | `systemctl stop nginx` and `systemctl stop ufw`                              |
| Web-root permissions were weakened            | High                          | Recursive `chmod 777`                                                        |
| Privilege persistence was established         | High                          | `/etc/sudoers` modification                                                  |
| shell.php is a web shell                      | High, but not directly proven | Access pattern + surrounding compromise activity                             |
| 10.74 GiB was successfully exfiltrated        | Not confirmed                 | HTTP response size does not prove complete external receipt                  |

---

## 6.15 MITRE ATT&CK Alignment

The observed WEB-01 activity maps to several ATT&CK behaviors:

| Observed Activity                  | ATT&CK Technique                                                                                                                                                                       | Rationale                                                                               |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| WordPress login abuse              | T1078 – Valid Accounts                                                                                                                                                                 | Successful authenticated access is indicated, although the credential source is unknown |
| `whoami`, `hostname`, `ip a`       | T1033 – System Owner/User Discovery and T1016 – System Network Configuration Discovery                                                                                                 | Direct host and network reconnaissance                                                  |
| `wget update.sh`                   | T1105 – Ingress Tool Transfer                                                                                                                                                          | Tool/payload transferred to the compromised host                                        |
| `bash /tmp/update.sh`              | T1059.004 – Unix Shell                                                                                                                                                                 | Shell-based execution                                                                   |
| `systemctl stop ufw`               | T1562.001 – Impair Defenses: Disable or Modify Tools                                                                                                                                   | Host firewall disabled                                                                  |
| `/etc/sudoers` modification        | T1548.003 – Sudo and Sudo Caching                                                                                                                                                      | Sudo configuration altered to provide elevated execution                                |
| `shell.php`                        | T1505.003 – Server Software Component: Web Shell                                                                                                                                       | Evidence strongly indicates web-shell activity                                          |
| Repeated `backup.tar.gz` retrieval | Potential T1567.002 – Exfiltration to Cloud Storage only if destination is confirmed as a cloud service; otherwise the technique cannot be confidently assigned from the supplied logs | Destination and transfer path require corroboration                                     |

The MITRE mapping should remain evidence-driven. In particular, a large HTTP download should not automatically be classified as a specific exfiltration technique without establishing where the data went.

---

## 6.16 Incident Significance

WEB-01 should be treated as a confirmed compromised server and a probable staging point for subsequent intrusion activity.

The critical evidence is not any individual event but the progression across multiple telemetry types:

```text
Authentication Abuse
        +
Authenticated Application Access
        +
SSH Access
        +
Reconnaissance
        +
Payload Execution
        +
Defense Modification
        +
Privilege Configuration
        +
Web Shell
        +
Large-Scale Archive Access
```

This combination materially exceeds the threshold for a suspicious event and constitutes a confirmed host compromise.

The most important unresolved questions following the WEB-01 compromise are:

1. How were the WordPress credentials obtained?
2. How did the attacker obtain valid SSH credentials for www-data?
3. What was contained in `backup.tar.gz`?
4. Was the archive completely transferred to an attacker-controlled destination?
5. What exactly did `update.sh` execute?
6. Was `shell.php` created through the WordPress application, SSH access, or the downloaded payload?
7. How did the attacker transition from WEB-01 to PC-MANAGER and subsequently to DC-01?

These questions should be investigated using authentication logs, WordPress audit/application logs, filesystem telemetry, process execution logs, network-flow data, DNS/proxy telemetry, and any available endpoint detection data.

**Current conclusion:** WEB-01 is the earliest asset with a high-confidence, fully observable malicious attack chain in the supplied evidence, and its compromise provides the strongest foundation for reconstructing the subsequent enterprise intrusion.
