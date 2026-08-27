# 18. Final Incident Assessment

## 18.1 Assessment Basis

This assessment is based exclusively on the telemetry provided for the incident window. Findings are classified according to the strength of the available evidence:

* **Confirmed** — directly supported by one or more observed log events.
* **Highly likely** — strongly supported by correlated evidence, but lacking one piece of direct forensic confirmation.
* **Unconfirmed** — plausible, but the available telemetry is insufficient to establish the activity as fact.

The incident should be assessed as a multi-stage compromise involving WEB-01, subsequent compromise of privileged identities, execution and persistence on Windows systems, command-and-control activity, and attempted or potential access to sensitive data.

---

## 18.2 Confirmed Malicious Activity

### WEB-01: Successful Initial Compromise and Post-Compromise Execution

The following web activity establishes a successful authentication attack followed by access to administrative functionality:

```text
09:00:00 - GET /wp-login.php
09:00:01–09:00:34 - POST /wp-login.php (34 requests)
09:00:35 - GET /wp-admin/
09:00:36 - POST /admin-ajax.php
09:00:37 - GET /backup.tar.gz
```

The transition from repeated authentication attempts to /wp-admin/ and subsequent access to backup.tar.gz provides strong evidence of successful compromise rather than reconnaissance alone.

The subsequent host activity further establishes post-compromise execution:

```text
09:05:00 - Accepted password for www-data from 45.33.22.11
09:05:05 - whoami && hostname && ip a
09:05:10 - wget update.sh
09:05:15 - downloading secondary payload
09:05:20 - bash /tmp/update.sh
```

These events demonstrate authenticated access, host reconnaissance, payload retrieval, and payload execution.

**Assessment:** Confirmed compromise of WEB-01.

---

### Persistence and Security Control Modification

The following commands were subsequently observed:

```text
09:05:25 - systemctl stop nginx
09:05:30 - systemctl stop ufw
09:05:35 - chmod 777 /var/www/html -R
09:05:40 - echo 'www-data ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
```

Stopping ufw, recursively changing permissions on the web root, and modifying sudoers to grant www-data passwordless administrative execution are not consistent with routine web-server administration in this context.

The sudoers modification is particularly significant because it establishes a persistent privilege mechanism for the compromised account.

**Assessment:** Confirmed post-compromise persistence and security-control modification on WEB-01.

---

### Web Shell Deployment and Continued Access

The following events were observed:

```text
09:06:00 - GET /shell.php
09:06:01 - POST /shell.php
```

Later activity confirms continued interaction with the same resource:

```text
13:00:00 - GET shell.php
13:00:01 - POST shell.php
13:00:02 - GET backup.tar.gz
```

The repeated GET/POST interaction with shell.php, combined with the preceding payload execution and later file access, is consistent with a web shell being used as a persistent remote execution interface.

**Assessment:** Confirmed malicious web-shell activity on WEB-01.

---

## 18.3 Confirmed Command-and-Control Activity

The Windows telemetry contains repeated outbound connections from a newly created service process:

```text
09:40:02 - Service Created: SysUpdate
09:40:03 - svchost.exe → 194.34.132.15:4444
```

The later telemetry shows the same destination repeatedly:

```text
11:00:05 onward - 5156
Process: C:\ProgramData\svchost.exe
Destination: 194.34.132.15:4444
Protocol: TCP
Action: Allow
```

The same pattern appears again on DC-01:

```text
20:00:04 - Service Created: SysUpdate
20:00:05 onward - C2 Connection to 194.34.132.15:4444
```

The significance does not depend solely on TCP/4444. The combination of:

1. encoded PowerShell,
2. execution of a binary from C:\ProgramData,
3. creation of a service named SysUpdate,
4. immediate outbound communication,
5. repeated communication to the same external destination,

provides the basis for assessing the traffic as malicious command-and-control activity.

**Assessment:** Confirmed C2 infrastructure/activity associated with 194.34.132.15:4444.

---

## 18.4 Confirmed Windows Persistence and Execution

The following sequence was recorded:

```text
09:40:00 - cmd.exe /c whoami
09:40:01 - PowerShell -Enc
09:40:02 - Service Created: SysUpdate
09:40:03 - svchost.exe → 194.34.132.15:4444
```

The encoded PowerShell command contains a download-and-execution pattern:

```text
...New-Object Net.WebClient).DownloadString(...)
```

The service creation immediately following the PowerShell execution is highly indicative of an attempt to establish persistent execution.

A comparable sequence was later observed at 11:00:

```text
11:00:00 - Logon Type 10
11:00:01 - 4672
11:00:02 - cmd /c whoami
11:00:03 - PowerShell -Enc
11:00:04 - Service Created: SysUpdate
```

The same persistence mechanism therefore appears to have been reproduced rather than occurring as an isolated administrative action.

**Assessment:** Confirmed malicious process execution and service-based persistence on the affected Windows system(s).

---

## 18.5 Credential and Account Compromise

The following database activity was observed:

```text
09:30 - backup: SELECT customers, orders
09:35 - dbadmin:
SELECT wp_users,
UPDATE user_pass
```

The UPDATE user_pass operation directly modifies WordPress authentication data.

Additional activity was observed later:

```text
12:00 - backup:
SELECT customers, wp_users,
UPDATE user_pass
```

This demonstrates repeated interaction with the WordPress user database and modification of authentication credentials.

Separately, the web logs show activity attributed to maryam:

```text
09:20:00 - GET /wp-admin/
09:20:01 - POST /admin-ajax.php
09:20:02 - GET /backup.tar.gz
```

and later:

```text
18:00:00 - GET /wp-admin/
18:00:01 - POST /admin-ajax.php
18:00:02 - GET /backup.tar.gz
```

The available evidence strongly indicates that the maryam identity was involved in suspicious activity. However, the logs do not independently establish whether the legitimate user knowingly performed these actions or whether the account credentials had been compromised.

**Assessment:** Confirmed unauthorized modification of WordPress authentication data; compromise of the maryam credentials is highly likely but should remain an investigative finding rather than an absolute fact.

---

## 18.6 Lateral Movement and Domain-Level Compromise

The following event was recorded on DC-01:

```text
20:00:00 - 4624 Logon Type 10
User: maryam
Source IP: 192.168.1.100
20:00:01 - 4672
User: maryam
20:00:02 - cmd /c whoami
20:00:03 - PowerShell -Enc
20:00:04 - Service Created: SysUpdate
20:00:05 - C2 Connection to 194.34.132.15:4444
```

This is highly significant because the same malicious execution and persistence sequence previously observed elsewhere appears on the Domain Controller.

However, the supplied logs do not provide a complete network authentication chain showing exactly how the attacker moved from WEB-01 to PC-MANAGER and subsequently to DC-01.

Likewise, Logon Type 10 establishes a remote interactive logon, but the supplied Source IP: 192.168.1.100 does not by itself identify the originating attacker-controlled host.

Therefore:

**Assessment:** Compromise of DC-01 is confirmed by the malicious execution, persistence, and C2 telemetry. The precise lateral-movement path to DC-01 remains unconfirmed.

---

## 18.7 Data Access and Potential Exfiltration

The web logs contain repeated successful downloads:

```text
09:06:02–09:15:30 - GET /backup.tar.gz
Approximately 110 requests
HTTP 200
Size: 104857600 bytes per response
```

Additional activity was recorded:

```text
09:20:02 - GET /backup.tar.gz
Approximately 15 requests
```

and:

```text
13:00:02 - GET backup.tar.gz
49 requests
```

and:

```text
18:00:02 - GET /backup.tar.gz
100 requests
```

The file size represented by each successful response is approximately 100 MiB.

If every response represents a complete transfer, the observed requests could represent approximately 26 GiB of HTTP response data across the supplied periods. However, HTTP request count and response size alone do not prove that the complete payload was delivered to an attacker.

There is also no supplied network-flow or proxy telemetry establishing the actual number of bytes transferred externally.

**Assessment:** Unauthorized access to and repeated retrieval of backup.tar.gz is confirmed. Data exfiltration is highly likely but not conclusively proven by the supplied evidence.

---

## 18.8 Phishing Evidence

The following email telemetry was observed:

```text
09:45:03–09:45:07
From: 194.34.132.15
Attachment: invoice_pdf.exe
```

The sender corresponds to the same infrastructure later associated with C2:

```text
194.34.132.15:4444
```

However, the email appears after the first observed malicious execution on PC-MANAGER:

```text
09:40:00 - cmd.exe /c whoami
09:40:01 - PowerShell -Enc
09:40:02 - Service Created: SysUpdate
09:40:03 - C2 connection
```

Therefore, the supplied evidence cannot establish this email as the initial access vector.

**Assessment:** Malicious/phishing activity is strongly suspected. Its role as the initial access mechanism is unconfirmed.

---

## 18.9 Overall Incident Determination

Based on the available evidence, the incident should be classified as a:

> **Confirmed Multi-Host Compromise with Persistent Remote Access, Command-and-Control Activity, Credential/Account Abuse, and Potential Data Exfiltration.**

The strongest confirmed elements of the incident are:

1. WEB-01 compromise
2. Malicious payload execution
3. Web-shell activity
4. Persistence through sudoers modification
5. Windows service-based persistence
6. Encoded PowerShell execution
7. C2 communication with 194.34.132.15:4444
8. Repeated modification of WordPress authentication data
9. Malicious execution and persistence on DC-01
10. Repeated unauthorized retrieval of backup.tar.gz

The following remain unresolved:

1. The true initial access vector.
2. The exact lateral-movement path between compromised hosts.
3. Whether maryam's credentials were definitely stolen or whether some activity was legitimately performed by the user.
4. Whether all observed backup.tar.gz requests resulted in complete external data transfer.
5. The exact contents and capabilities of the downloaded payloads.
6. The precise role of the 09:45 phishing email.

---

## 18.10 Severity Determination

The presence of confirmed malicious execution and persistence on a Domain Controller, combined with recurring C2 communication, warrants a Critical-severity incident classification.

The severity is not based on the number of suspicious requests alone. It is driven by the combination of:

```text
WEB-01
  ↓
Payload execution
  ↓
Web shell / persistence
  ↓
Credential and account abuse
  ↓
Windows execution
  ↓
Service persistence
  ↓
194.34.132.15:4444 C2
  ↓
DC-01 compromise
```

The compromise of DC-01 materially increases the potential blast radius because the affected system is a domain-level identity and infrastructure component.

---

## 18.11 Final Confidence Statement

| Finding                    | Confidence                                                                 |
| -------------------------- | -------------------------------------------------------------------------- |
| Incident existence         | Confirmed                                                                  |
| WEB-01 compromise          | Confirmed                                                                  |
| Web shell                  | Confirmed                                                                  |
| Persistence                | Confirmed                                                                  |
| C2                         | Confirmed                                                                  |
| Credential/account abuse   | Confirmed for WordPress credentials; maryam compromise highly likely       |
| DC-01 compromise           | Confirmed                                                                  |
| Lateral movement path      | Unconfirmed                                                                |
| Phishing as initial access | Unconfirmed                                                                |
| Unauthorized backup access | Confirmed                                                                  |
| Actual data exfiltration   | Highly likely, but not conclusively demonstrated by the supplied telemetry |
| Overall severity           | Critical                                                                   |

**Final assessment:** The available telemetry is sufficient to establish that this was not a collection of isolated anomalous events. The events form a coherent intrusion sequence involving initial compromise of the web environment, establishment of persistence, execution of malicious code, C2 communication, abuse of credentials, and subsequent compromise of a Domain Controller. The principal remaining investigative question is not whether a compromise occurred, but how the attacker initially obtained access and how the compromise propagated between the affected assets.
