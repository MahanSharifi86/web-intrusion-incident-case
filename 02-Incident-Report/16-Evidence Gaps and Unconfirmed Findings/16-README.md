# 16. Evidence Gaps and Unconfirmed Findings

## 16.1 Purpose

This section distinguishes between facts directly supported by the available telemetry and conclusions that remain unconfirmed because the evidence set is incomplete.

The investigation contains sufficient evidence to establish a significant compromise. However, several important questions cannot be answered conclusively from the supplied logs alone.

The absence of evidence in this section should not be interpreted as evidence that the corresponding activity did not occur.

---

## 16.2 Initial Access — Unconfirmed

The precise initial access vector remains undetermined.

The earliest clearly malicious activity currently available is:

```text
09:00:00 - GET /wp-login.php
09:00:01–09:00:34 - POST /wp-login.php
09:00:35 - GET /wp-admin/
09:00:36 - POST /admin-ajax.php
09:00:37 - GET /backup.tar.gz
```

This establishes a successful authentication sequence followed immediately by administrative web activity and retrieval of a backup file.

However, these logs do not establish how the attacker originally obtained the credentials or access necessary to authenticate.

A later email event is available:

```text
09:45:03–09:45:07 - From: 194.34.132.15
Attachment: invoice_pdf.exe
```

Because this occurs after the 09:40 malicious activity on PC-MANAGER, it cannot currently be treated as the initial access event for that compromise.

### Assessment

**Status:** Unconfirmed.

**Required evidence:**

* Earlier email gateway logs
* Authentication logs preceding 09:00
* WordPress authentication/audit logs
* VPN/RDP/SSH authentication telemetry
* Endpoint telemetry preceding the first confirmed malicious event
* Web application security logs

---

## 16.3 Source of www-data SSH Credentials — Unconfirmed

The following event is confirmed:

```text
09:05:00 - Accepted password for www-data from 45.33.22.11
```

The successful authentication establishes unauthorized access to WEB-01.

However, the available evidence does not establish whether the credentials were:

* stolen,
* reused,
* discovered from the exposed backup,
* obtained through the WordPress compromise,
* obtained through another compromised host, or
* otherwise exposed.

No credential-theft telemetry is provided.

### Assessment

**Status:** Confirmed unauthorized authentication; credential acquisition method unconfirmed.

---

## 16.4 Whether www-data Obtained Root — Not Directly Proven

The following activity is highly significant:

```text
09:05:35 - chmod 777 /var/www/html -R
09:05:40 - echo 'www-data ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
```

These actions strongly indicate that the attacker obtained sufficient privileges to modify `/etc/sudoers`.

However, the supplied logs do not contain an explicit:

```text
whoami → root
```

or equivalent privilege-transition event.

Therefore, it is inappropriate to state solely from these logs that the original www-data session was already operating as root.

What is supported is that the attacker successfully modified the system's privilege configuration in a manner that could grant www-data passwordless administrative execution.

### Assessment

**Status:** Privileged modification confirmed; exact privilege-escalation path unconfirmed.

---

## 16.5 Web Shell Upload Mechanism — Unconfirmed

The following activity is available:

```text
09:06:00 - GET /shell.php
09:06:01 - POST /shell.php
```

This strongly supports the presence and subsequent use of a web shell.

However, the supplied logs do not show the event that created `shell.php`.

There is no corresponding upload operation, file-write event, exploit request, or filesystem telemetry in the evidence provided.

### Assessment

**Confirmed:** `shell.php` was accessed and interacted with.

**Unconfirmed:** How `shell.php` was introduced into WEB-01.

Required evidence would include:

* HTTP upload requests
* Nginx access/error logs surrounding file creation
* Filesystem auditing
* Web application logs
* EDR file-creation telemetry

---

## 16.6 Nature of update.sh and Secondary Payload — Unconfirmed

The following events are recorded:

```text
09:05:10 - wget update.sh
09:05:15 - downloading secondary payload
09:05:20 - bash /tmp/update.sh
```

This establishes attacker-controlled download and execution activity.

However, the actual contents, hashes, execution behavior, and persistence mechanisms of `update.sh` and the secondary payload are not present in the evidence set.

### Assessment

**Status:** Malicious execution strongly supported; payload functionality unconfirmed.

The investigation should therefore avoid claiming a specific malware family or capability without corresponding binary/script evidence.

---

## 16.7 C2 Functionality — Strongly Supported but Not Fully Characterized

The following telemetry is available:

```text
09:40:03 - C:\ProgramData\svchost.exe
            → 194.34.132.15:4444
```

followed by repeated connections.

Later:

```text
11:00:05 onward - 5156 → 194.34.132.15:4444
```

and:

```text
20:00:05 - C2 Connection to 194.34.132.15:4444
```

This establishes repeated outbound communication between the suspicious process and the same external endpoint.

However, the logs do not provide:

* Payload contents
* C2 protocol
* Beacon interval
* Commands received
* Commands executed through C2
* Amount of data exchanged
* Whether the endpoint was attacker infrastructure or a legitimate service

### Assessment

**Status:** C2 activity strongly supported; exact C2 protocol and command set unconfirmed.

The port number 4444 alone is not evidence of C2. The conclusion is based on the combination of the suspicious process, persistence mechanism, external destination, and repeated communications.

---

## 16.8 SysUpdate Service Scope — Partially Confirmed

The following event exists on PC-MANAGER:

```text
09:40:02 - Service Created: SysUpdate
Image Path: C:\ProgramData\svchost.exe
```

A similar event occurs later on DC-01:

```text
20:00:04 - Service Created: SysUpdate
```

This strongly suggests the same persistence strategy was deployed on multiple Windows hosts.

However, the supplied evidence does not establish:

* Whether the executable was identical on both systems
* File hashes
* Service account
* Service configuration
* Service start/stop history
* Whether SysUpdate was created by the same intrusion
* Whether the service successfully executed on both systems

### Assessment

**Status:** Suspicious persistence mechanism strongly supported; exact implementation and deployment path unconfirmed.

---

## 16.9 PC-MANAGER Initial Compromise — Unconfirmed

The earliest supplied malicious activity on PC-MANAGER is:

```text
09:40:00 - cmd.exe /c whoami
09:40:01 - PowerShell -Enc
09:40:02 - Service Created: SysUpdate
09:40:03 - svchost.exe → 194.34.132.15:4444
```

This proves malicious post-compromise behavior but does not show the event immediately preceding it.

The available evidence therefore does not identify whether PC-MANAGER was compromised through:

* stolen credentials,
* remote access,
* exploitation,
* malware execution,
* lateral movement from WEB-01,
* or another host.

### Assessment

**Status:** Host compromise supported; initial access mechanism unconfirmed.

---

## 16.10 Relationship Between WEB-01 and PC-MANAGER — Not Directly Proven

The overall chronology suggests a relationship between the compromises.

However, the supplied logs do not contain a direct event showing:

```text
WEB-01 → PC-MANAGER
```

or an equivalent network/authentication event.

The evidence establishes:

```text
WEB-01
09:00–09:06  Compromise and persistence activity
        ↓
PC-MANAGER
09:40        Command execution + persistence + C2
```

but the intermediate transmission mechanism is absent.

### Assessment

**Status:** Temporal relationship established; direct lateral-movement path unconfirmed.

This distinction is important. A professional incident report should not convert chronological proximity into a proven causal relationship.

---

## 16.11 maryam Credential Compromise — Strongly Suspected, Mechanism Unknown

The following event establishes privileged interactive activity:

```text
08:07:00 - 4624 Logon Type 10, User: maryam
08:07:01 - 4672 Special Privileges, User: maryam
```

Later:

```text
18:00:00 - GET /wp-admin/
18:00:01 - POST /admin-ajax.php
18:00:02 - GET /backup.tar.gz
```

The activity is suspicious because it resembles the previously observed attacker workflow.

However, the evidence does not prove that:

* maryam personally performed the activity,
* her password was stolen,
* her credentials were reused by an attacker,
* a session token was stolen,
* or the attacker impersonated her through another mechanism.

### Assessment

**Status:** Account compromise strongly suspected; credential acquisition mechanism unconfirmed.

---

## 16.12 Logon Type 10 Does Not Establish Remote Attack by Itself

The relevant event is:

```text
20:00:00 - 4624 Logon Type 10
User: maryam
```

Logon Type 10 indicates a Remote Interactive logon.

However, the supplied telemetry does not provide enough surrounding authentication context to reconstruct the exact remote source and session path.

Similarly:

```text
08:07:00 - 4624 Logon Type 10
User: maryam
Source IP: 192.168.1.100
```

does not independently establish that an external attacker remotely controlled the machine.

### Assessment

**Status:** Remote interactive authentication confirmed; attacker attribution to the session unconfirmed from this event alone.

---

## 16.13 10.10.10.200 Brute-Force Activity — Requires Environmental Validation

The supplied event is:

```text
08:30:00–08:30:20
4625 Logon Type 3
User: Administrator
Source IP: 10.10.10.200
21 failed attempts
```

The event pattern is consistent with repeated failed network authentication.

However, determining whether this represents malicious brute force or legitimate security tooling requires asset identification.

If `10.10.10.200` is an authorized vulnerability scanner or security assessment system, the activity could represent a false positive.

### Assessment

**Status:** Repeated failed authentication confirmed; malicious intent unconfirmed.

This IP must therefore be correlated against:

* Asset inventory
* Vulnerability scanner configuration
* Scheduled security scans
* Change-management records
* Authentication baselines

---

## 16.14 backup.tar.gz — Exfiltration Not Fully Proven

The strongest relevant evidence is:

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

Earlier activity also shows:

```text
09:00:37 - GET /backup.tar.gz
```

The object is recorded as:

```text
104857600 bytes
```

in the provided Nginx telemetry.

This demonstrates repeated successful HTTP responses for a 100 MiB object.

However, HTTP request count is not equivalent to confirmed exfiltrated volume.

The logs do not establish:

* TCP completion for every transfer
* Whether clients received the complete object
* Whether transfers were interrupted
* Destination-side receipt
* Destination-side storage
* Whether the file contents were subsequently used

### Assessment

**Status:** Repeated unauthorized retrieval strongly supported; exact exfiltration volume and successful attacker retention unconfirmed.

---

## 16.15 Database Data Exfiltration — Unconfirmed

The following query is available:

```text
09:30 - backup: SELECT customers, orders
```

This proves database access to customer and order records.

However, a `SELECT` statement alone does not establish that the returned data left the database environment.

Similarly:

```text
09:35 - dbadmin: SELECT wp_users, UPDATE user_pass
```

confirms access to the WordPress user table and modification of authentication data, but does not prove that the entire table was extracted.

### Assessment

**Status:** Database access confirmed; database exfiltration unconfirmed.

---

## 16.16 Phishing Email — Causality Unconfirmed

The available email evidence is:

```text
09:45:03–09:45:07
From: 194.34.132.15
Attachment: invoice_pdf.exe
```

The executable attachment is suspicious and the sender corresponds to the previously observed C2 destination.

However, the event occurs after:

```text
09:40:00 - cmd.exe /c whoami
09:40:01 - PowerShell -Enc
09:40:02 - Service Created: SysUpdate
09:40:03 - C2 → 194.34.132.15:4444
```

Therefore, this email cannot currently explain the initial compromise of PC-MANAGER at 09:40.

It may represent:

* a secondary phishing wave,
* attacker persistence/propagation,
* a separate malicious campaign,
* or an event generated after compromise.

### Assessment

**Status:** Malicious-looking email strongly suspicious; role in the attack chain unconfirmed.

---

## 16.17 DC-01 Domain Compromise — Host Compromise Confirmed; Domain-Wide Takeover Not Proven

The evidence on DC-01 is severe:

```text
20:00:00 - 4624 Logon Type 10, User: maryam
20:00:01 - 4672
20:00:02 - cmd /c whoami
20:00:03 - PowerShell -Enc
20:00:04 - Service Created: SysUpdate
20:00:05 - C2 → 194.34.132.15:4444
```

This supports compromise of the Domain Controller.

However, the supplied logs do not demonstrate:

* Domain Admin membership
* DCSync
* Kerberos ticket theft
* KRBTGT compromise
* NTDS.dit access
* Domain-wide credential dumping
* creation of additional privileged domain accounts
* Group Policy modification

### Assessment

**Status:** DC-01 compromise strongly supported/should be treated as confirmed for incident response purposes; complete Active Directory takeover remains unconfirmed.

---

## 16.18 Backup Infrastructure — Insufficient Evidence

The available telemetry shows:

```text
22:00:00 - 4624 Logon Type 3
User: Veeam
Source IP: 172.16.10.50
Share: \BACKUP-01\Backup
```

and:

```text
22:00:01–22:00:25
C:\Program Files\Veeam\Backup.exe
→ 172.16.10.50:443
```

This activity is consistent with legitimate backup operations.

The available logs do not show attacker interaction with BACKUP-01.

Therefore, there is insufficient evidence to classify the backup server as compromised.

### Assessment

**Status:** No confirmed compromise; environmental validation required.

---

## 16.19 Exact Data Loss — Unquantified

Although repeated retrieval of `backup.tar.gz` is evident, the evidence set does not provide a defensible final figure for the amount of information actually lost.

The observed object size is:

```text
104857600 bytes
```

or approximately 100 MiB per complete response.

Multiplying object size by request count would assume that every request resulted in a complete, independently transferred object. That assumption cannot be validated from the supplied Nginx logs alone.

### Assessment

**Status:** Potential data loss is significant; exact volume remains unquantified.

---

## 16.20 Evidence Required to Close the Major Gaps

The following telemetry would materially improve confidence in the investigation:

| Evidence Source                     | Primary Investigation Question                             |
| ----------------------------------- | ---------------------------------------------------------- |
| Nginx access/error logs             | How was the web application compromised?                   |
| WordPress audit/authentication logs | Which account authenticated and how?                       |
| Linux auditd / EDR                  | What executed on WEB-01 and with which privileges?         |
| Filesystem telemetry                | When and how were shell.php and payloads created?          |
| Windows Security logs               | What authenticated to PC-MANAGER and DC-01?                |
| Sysmon / EDR                        | Full process trees, hashes and network connections         |
| PowerShell logs                     | What did the encoded PowerShell command execute?           |
| DNS telemetry                       | Domain resolution and C2 infrastructure                    |
| Firewall / NetFlow                  | Actual transferred bytes and communication direction       |
| Database audit logs                 | Exact records accessed and modified                        |
| Email gateway logs                  | Whether phishing preceded compromise                       |
| Active Directory logs               | Privilege escalation and domain-wide activity              |
| Asset inventory                     | Ownership and purpose of 10.10.10.200                      |
| Veeam audit logs                    | Whether backup infrastructure was accessed by the attacker |

---

## 16.21 Investigation Confidence

Based on the supplied evidence:

| Finding                                                         | Confidence                   |
| --------------------------------------------------------------- | ---------------------------- |
| WEB-01 was compromised                                          | High                         |
| Attacker executed commands on WEB-01                            | High                         |
| Persistence was established on WEB-01                           | High                         |
| shell.php was used                                              | High                         |
| Security controls on WEB-01 were weakened                       | High                         |
| PC-MANAGER was compromised                                      | High                         |
| SysUpdate represents malicious persistence                      | High                         |
| C2 communication with 194.34.132.15:4444 occurred               | High                         |
| DC-01 was compromised                                           | High                         |
| maryam credentials/session were abused                          | Medium–High                  |
| backup.tar.gz was repeatedly retrieved by unauthorized activity | High                         |
| Database records were accessed                                  | High                         |
| Database data was exfiltrated                                   | Medium / Unconfirmed         |
| Complete backup.tar.gz contents were exfiltrated                | Medium / Unconfirmed         |
| Exact initial access vector                                     | Low                          |
| Phishing was the initial access vector                          | Low                          |
| Direct WEB-01 → PC-MANAGER lateral movement                     | Medium / Unconfirmed         |
| Domain-wide takeover                                            | Medium / Unconfirmed         |
| BACKUP-01 compromise                                            | Low / No supporting evidence |

---

## 16.22 Final Evidence-Gap Assessment

The evidence gaps do not materially weaken the conclusion that a serious security incident occurred.

The available telemetry is sufficient to establish a progression involving initial web-server compromise, execution, persistence, credential/account abuse, C2 communication, subsequent Windows host compromise, and access to sensitive data.

The principal unresolved questions concern causality and scope, rather than the existence of malicious activity:

1. How did the attacker obtain the initial credentials/access?
2. How did the attacker move from WEB-01 to PC-MANAGER?
3. How were maryam credentials or session access obtained?
4. What exactly did the encoded PowerShell payload execute?
5. What data was actually transferred outside the environment?
6. How far did the compromise extend within Active Directory?
7. Was BACKUP-01 ever accessed or compromised?

Until these questions are resolved through additional telemetry, the investigation should preserve the distinction between confirmed compromise, strongly supported assessment, and unconfirmed hypothesis. This prevents the final incident report from overstating what the evidence can actually prove.
