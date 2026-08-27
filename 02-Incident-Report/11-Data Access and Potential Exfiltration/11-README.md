# 11. Data Access and Potential Exfiltration

## 11.1 Assessment

The available evidence demonstrates repeated successful access to a large backup archive on WEB-01, followed by repeated retrieval of the same object.

The logs establish unauthorized or at minimum highly suspicious access to:

```text
/backup.tar.gz
```

with each successful HTTP response reporting:

```text
HTTP 200
Size: 104857600 bytes
```

However, the logs provided do not independently prove that the entire reported response size was successfully delivered to an attacker-controlled destination. Therefore, the incident should distinguish between:

* Confirmed data access
* Observed HTTP retrieval
* Potential data exfiltration
* Confirmed exfiltration volume

The evidence is sufficient to treat the archive as a high-priority potential data-exfiltration event, but the exact amount of data successfully exfiltrated cannot be established from the HTTP access logs alone.

---

## 11.2 Sensitive Archive Access on WEB-01

The earliest significant evidence is the repeated retrieval of the backup archive.

At 09:00, the web server records:

```text
09:00:37 - GET /backup.tar.gz
```

The surrounding activity is significant because it follows repeated authentication attempts against the WordPress login endpoint:

```text
09:00:00 - GET /wp-login.php
09:00:01–09:00:34 - POST /wp-login.php
09:00:35 - GET /wp-admin/
09:00:36 - POST /admin-ajax.php
09:00:37 - GET /backup.tar.gz
```

The sequence is consistent with:

```text
Authentication activity
        ↓
Administrative interface access
        ↓
Archive retrieval
```

The archive is therefore not an isolated HTTP request. It occurs immediately after suspicious authentication activity and administrative access.

This correlation materially increases its significance.

---

## 11.3 Archive Size

The web server reports:

```text
HTTP Status: 200
Response Size: 104857600 bytes
```

104,857,600 bytes is approximately 100 MiB.

Therefore, every logged successful response represents approximately 100 MiB of HTTP response data according to the server log.

This is important because the archive is not a small configuration file or ordinary WordPress resource. Its size is consistent with a substantial backup object and potentially contains application, configuration, user, or database information.

The logs themselves, however, do not reveal the archive's internal contents.

Therefore:

> The presence of potentially sensitive data inside backup.tar.gz must be treated as an investigative hypothesis until the archive inventory or backup-generation records confirm its contents.

---

## 11.4 Repeated Retrieval Activity

The strongest evidence of potential exfiltration occurs between 09:06 and 09:15.

The supplied logs indicate:

```text
09:06:02–09:15:30
GET /backup.tar.gz
Approximately 110 requests
HTTP 200
Response Size: 104857600 bytes
```

The repeated retrieval of the same 100-MiB object over approximately nine minutes is not consistent with ordinary browsing behavior.

A legitimate administrator may download a backup once.

Repeated successful retrievals of the same large archive are materially different from that baseline.

The pattern is therefore assessed as:

**Confirmed:** repeated HTTP retrieval of the archive.

**Highly suspicious:** repeated retrieval by an attacker-associated session.

**Not yet confirmed:** successful exfiltration of the full theoretical response volume.

---

## 11.5 Theoretical Transfer Volume

If all approximately 110 responses were completely transmitted, the maximum response volume represented by the access records would be:

```text
110 × 104857600 bytes
= 11,534,336,000 bytes
```

This is approximately:

```text
10.74 GiB
```

This figure should not be reported as "10.74 GiB exfiltrated" without qualification.

The correct incident-report wording is:

> The access logs record approximately 110 successful responses for a 100-MiB archive, representing approximately 10.74 GiB of logged HTTP response volume if each response was fully delivered. Network-level telemetry is required to confirm the actual amount of data transmitted and received.

This distinction is important in a forensic report.

An HTTP access log demonstrates that the server processed the request and recorded a response size. It does not necessarily establish the complete end-to-end transfer.

---

## 11.6 Access Under the maryam Identity

A second important sequence occurs at 09:20:

```text
09:20:00 - GET /wp-admin/
09:20:01 - POST /admin-ajax.php
09:20:02 - GET /backup.tar.gz
```

The archive is subsequently retrieved repeatedly:

```text
09:20:02 onward
GET /backup.tar.gz
Approximately 15 requests
```

This is significant because the same behavioral sequence previously observed during the suspicious 09:00 activity appears again:

```text
/wp-admin/
/admin-ajax.php
/backup.tar.gz
```

The evidence therefore supports the hypothesis that the maryam identity was being used in activity associated with archive access.

It does not, by itself, establish whether:

1. Maryam personally performed the activity;
2. an attacker possessed her credentials;
3. an existing compromised session was being reused;
4. the web application was performing the requests on her behalf.

Consequently, attribution to Maryam personally would be inappropriate without additional authentication and endpoint evidence.

---

## 11.7 Continued Archive Retrieval at 13:00

The strongest correlation between the archive and the identified C2 infrastructure appears at 13:00:

```text
13:00:00 - GET /shell.php
13:00:01 - POST /shell.php
13:00:02 - GET /backup.tar.gz
```

followed by:

```text
GET /backup.tar.gz
Approximately 49 requests
```

The significance of this sequence is substantially higher than the earlier archive requests.

The relevant chain is:

```text
C2-associated infrastructure
        ↓
Web Shell access
        ↓
POST to shell.php
        ↓
Repeated retrieval of backup.tar.gz
```

The previously observed C2 address is:

```text
194.34.132.15:4444
```

and the same infrastructure is associated elsewhere in the incident with malicious persistence and command execution.

Therefore, the 13:00 archive activity should be treated as strong evidence of attacker-controlled interaction with the compromised web environment.

Nevertheless, the provided web-access records do not expose the source IP field for these 13:00 requests. The relationship to 194.34.132.15 should therefore be described as correlated with the established C2 infrastructure, rather than claiming that the web log itself proves that exact source IP initiated every request.

---

## 11.8 Archive Retrieval at 18:00

A further retrieval pattern occurs at 18:00:

```text
18:00:00 - GET /wp-admin/
18:00:01 - POST /admin-ajax.php
18:00:02 - GET /backup.tar.gz
```

The supplied logs then show approximately 100 repeated retrievals of the archive.

Each response is recorded as:

```text
HTTP 200
104857600 bytes
```

This is particularly significant because it occurs after the earlier 17:00 logoff activity.

A user logoff does not prove that an attacker has disappeared from the environment. Conversely, the subsequent web requests do not by themselves prove that the attacker authenticated again.

What can be stated confidently is:

> Archive retrieval activity continued after the earlier user logoff, demonstrating that the web application remained capable of serving the sensitive archive and that the archive remained accessible during the later phase of the incident.

The identity and exact origin of these requests require additional web, authentication, and network telemetry.

---

## 11.9 Correlation of Archive Access Across the Incident

The observed archive activity can be summarized as follows:

| Time        | Activity                                                                        | Assessment                         |
| ----------- | ------------------------------------------------------------------------------- | ---------------------------------- |
| 09:00       | /wp-login.php authentication activity followed by /wp-admin/ and /backup.tar.gz | Highly suspicious                  |
| 09:06–09:15 | ~110 successful archive retrievals                                              | Highly suspicious                  |
| 09:20       | /wp-admin/ → /admin-ajax.php → archive retrieval                                | Suspicious                         |
| 13:00       | shell.php access followed by ~49 archive retrievals                             | High-confidence malicious activity |
| 18:00       | /wp-admin/ → /admin-ajax.php → ~100 archive retrievals                          | Highly suspicious                  |

The repeated appearance of the same archive across multiple phases of the incident strongly suggests that the file was an objective of the compromise rather than incidental web traffic.

---

## 11.10 Data Access vs. Exfiltration

Forensic terminology matters here.

### Confirmed Data Access

The logs demonstrate:

```text
GET /backup.tar.gz
HTTP 200
104857600 bytes
```

Therefore, server-side access to the archive is confirmed.

### Confirmed HTTP Retrieval

The server repeatedly records successful HTTP responses for the archive.

Therefore, repeated HTTP retrieval is confirmed.

### Confirmed Data Exfiltration

This requires stronger evidence.

The current logs do not provide:

* packet-level transfer confirmation;
* destination network-flow records for each transfer;
* TCP byte counters;
* HTTP connection completion information;
* proxy logs;
* firewall egress records tied to the archive transfer;
* evidence of the archive arriving on an attacker-controlled host.

Therefore:

> Confirmed exfiltration of a specific volume cannot be established from the supplied web logs alone.

### Potential Exfiltration

The combination of:

```text
Compromised WEB-01
        +
Web Shell
        +
Repeated archive retrieval
        +
Large response size
        +
Attacker-associated infrastructure
```

provides sufficient evidence to classify the activity as:

**High-confidence potential data exfiltration.**

---

## 11.11 Potential Data Exposure

The filename:

```text
backup.tar.gz
```

indicates an archive that may contain backup material.

However, the logs do not establish what was actually stored inside it.

Possible contents could include:

* application source/configuration;
* database dumps;
* user records;
* authentication-related material;
* WordPress configuration;
* credentials or secrets;
* operational backups.

These are potential contents, not confirmed findings.

The incident response process should therefore prioritize determining the archive's actual contents and sensitivity.

---

## 11.12 Impact Assessment

The potential impact is significant because the archive was repeatedly accessible from a compromised web server.

If the archive contains application or database backups, unauthorized acquisition could expose:

* business data;
* customer information;
* WordPress account information;
* application configuration;
* credentials or secrets;
* historical system information.

The evidence currently supports the following severity assessment:

| Assessment                            | Status          |
| ------------------------------------- | --------------- |
| Data exposure risk                    | High            |
| Confirmed unauthorized archive access | Yes             |
| Confirmed full archive exfiltration   | No              |
| Potential exfiltration                | High confidence |
| Confirmed exfiltration volume         | Not established |

---

## 11.13 Required Validation

To determine whether backup.tar.gz was actually exfiltrated, the following evidence should be correlated:

### Network Telemetry

Review firewall, NetFlow, proxy, IDS/IPS, or packet-capture records for WEB-01 during:

```text
09:00–09:15
09:20 onward
13:00 onward
18:00 onward
```

The objective is to identify outbound byte counts and external destinations associated with the HTTP sessions.

### Web Server Logs

Obtain complete Nginx records containing:

```text
source IP
request timestamp
request URI
status code
response bytes
request duration
HTTP Range headers
User-Agent
connection information
```

This is especially important because repeated GET requests for a large object can represent retries, range requests, interrupted transfers, or complete downloads.

### File-System Evidence

Determine:

```text
/var/www/html/.../backup.tar.gz
```

file metadata, including:

* creation time;
* modification time;
* ownership;
* permissions;
* SHA-256 hash;
* file size;
* access timestamps where reliable.

### Backup Contents

Inspect an isolated forensic copy of the archive and identify whether it contains:

```text
database dumps
credentials
API keys
configuration files
customer data
WordPress credentials
source code
private documents
```

### Destination Evidence

Search for the archive or its hash on known compromised systems and any available network endpoints.

The objective is to determine whether:

```text
backup.tar.gz
```

or an extracted copy was written to an attacker-controlled location.

---

## 11.14 Conclusion

The evidence establishes that backup.tar.gz, a 100-MiB archive, was repeatedly and successfully requested from WEB-01 throughout multiple phases of the incident.

The most significant evidence is:

```text
09:00:37
GET /backup.tar.gz
HTTP 200
104857600 bytes
```

followed by approximately 110 additional retrievals during the 09:06–09:15 period.

Further evidence shows:

```text
09:20
GET /wp-admin/
POST /admin-ajax.php
GET /backup.tar.gz
```

and later:

```text
13:00
GET /shell.php
POST /shell.php
GET /backup.tar.gz
```

with approximately 49 additional archive requests.

A final large retrieval sequence occurs at:

```text
18:00
GET /wp-admin/
POST /admin-ajax.php
GET /backup.tar.gz
```

with approximately 100 archive requests.

These events establish a persistent pattern of large-scale archive access associated with the broader compromise of WEB-01.

The access logs theoretically represent approximately 10.74 GiB of HTTP response volume during the ~110-request sequence if every response was fully delivered. This value must not be treated as confirmed exfiltration without network-level validation.

The appropriate incident conclusion is therefore:

> Unauthorized access and repeated retrieval of a potentially sensitive backup archive from WEB-01 are confirmed. The activity is strongly indicative of attempted or ongoing data exfiltration, particularly when correlated with the compromised web shell and attacker infrastructure. However, the exact quantity of data successfully exfiltrated and the external recipient cannot be conclusively established from the supplied web-server logs alone.
