# 17. Containment and Remediation Recommendations

## 17.1 Response Objective

The primary objective is to contain the confirmed compromise, prevent further attacker access, preserve forensic evidence, and restore the affected environment from a trusted state.

Because the available evidence indicates compromise of WEB-01, PC-MANAGER, and DC-01, remediation should not be limited to the initially compromised web server.

The presence of attacker-controlled persistence, credential manipulation, and C2 activity requires treatment of the incident as a multi-host compromise with potential Active Directory impact.

---

## 17.2 Immediate Containment

### 17.2.1 Isolate WEB-01

**Evidence:**

```text
09:05:00 - Accepted password for www-data from 45.33.22.11
09:05:20 - bash /tmp/update.sh
09:05:25 - systemctl stop nginx
09:05:30 - systemctl stop ufw
09:05:40 - echo 'www-data ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
```

WEB-01 should be immediately removed from normal network connectivity while preserving forensic evidence.

**Recommended actions:**

* Remove inbound Internet access.
* Restrict outbound communication.
* Preserve disk and memory where operationally feasible.
* Capture running processes, network connections, filesystem metadata and relevant logs before rebuilding.
* Do not simply delete `shell.php`, `update.sh`, or `svchost.exe` before evidence acquisition.

Because the attacker modified system security controls, the host should not be considered trustworthy even after deleting the known malicious files.

---

### 17.2.2 Block the Known C2 Infrastructure

**Evidence:**

```text
09:40:03 - C:\ProgramData\svchost.exe
            → 194.34.132.15:4444
```

and:

```text
11:00:05 onward - 5156 → 194.34.132.15:4444
```

and:

```text
20:00:05 - C2 Connection to 194.34.132.15:4444
```

The IP address should be blocked at appropriate network-control layers.

**Recommended controls:**

* Firewall egress block
* Proxy/SWG block where applicable
* DNS/security-platform IOC block where applicable
* EDR network containment
* SIEM detection for historical and future connections

Blocking the destination is containment, not remediation. A compromised host must still be investigated because the attacker may have additional C2 infrastructure.

---

## 17.3 Protect the Domain

### 17.3.1 Treat DC-01 as a Priority Incident

**Evidence:**

```text
20:00:00 - 4624 Logon Type 10, User: maryam
20:00:01 - 4672
20:00:02 - cmd /c whoami
20:00:03 - PowerShell -Enc
20:00:04 - Service Created: SysUpdate
20:00:05 - C2 Connection to 194.34.132.15:4444
```

Because attacker-associated activity reached the Domain Controller, containment must include the Active Directory trust boundary.

**Recommended actions:**

* Isolate DC-01 from unnecessary network communication while maintaining required domain-service continuity.
* Prevent external communication from the DC.
* Preserve volatile and disk evidence.
* Review all privileged authentication activity.
* Identify all sessions associated with maryam.
* Investigate SysUpdate.
* Search for additional unauthorized services, scheduled tasks, accounts and Group Policy changes.

A Domain Controller should not be returned to production merely because the visible malicious process has been removed.

---

## 17.4 Credential Containment

### 17.4.1 Protect maryam

**Evidence:**

```text
08:07:00 - 4624 Logon Type 10, User: maryam
08:07:01 - 4672 Special Privileges, User: maryam
```

and later:

```text
18:00:00 - GET /wp-admin/
18:00:01 - POST /admin-ajax.php
18:00:02 - GET /backup.tar.gz
```

The account should be treated as potentially compromised until investigation proves otherwise.

**Recommended actions:**

1. Disable or restrict the account temporarily where operationally feasible.
2. Reset the password using a trusted administrative workstation.
3. Revoke active sessions and authentication tokens where supported.
4. Review authentication history.
5. Review privileged group membership.
6. Search for reuse of the same credentials across systems.
7. Investigate whether the account possessed administrative privileges on PC-MANAGER or DC-01.

The password reset must occur after determining whether credential theft or active session compromise is suspected, because changing the password alone does not necessarily terminate an already-established session.

---

### 17.4.2 Protect the WordPress Administrative Accounts

**Evidence:**

```text
09:35 - dbadmin: SELECT wp_users, UPDATE user_pass
```

The WordPress authentication database has been modified.

**Recommended actions:**

* Reset affected WordPress administrator credentials.
* Invalidate existing WordPress sessions.
* Review all administrator accounts.
* Remove unauthorized accounts.
* Review administrator role assignments.
* Rotate application/database credentials potentially exposed through the backup.
* Inspect WordPress authentication and audit logs for unauthorized access.

---

### 17.4.3 Credential Rotation Strategy

Credential rotation should be performed from known-clean administrative systems.

Priority should be given to:

1. Domain administrative accounts
2. maryam
3. WordPress administrators
4. Database administrators
5. Service accounts
6. SSH credentials
7. Backup infrastructure credentials
8. Application/API secrets potentially contained in backup.tar.gz

Credentials should not be rotated indiscriminately before evidence preservation if doing so could destroy important investigative context.

---

## 17.5 Remove Persistence

### 17.5.1 Linux Persistence

**Evidence:**

```text
09:05:40 - echo 'www-data ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
```

The unauthorized sudoers modification must be removed.

However, remediation should include a broader search for persistence mechanisms:

* `/etc/sudoers`
* `/etc/sudoers.d/`
* SSH `authorized_keys`
* cron jobs
* systemd services
* init scripts
* shell profiles
* startup scripts
* web-server configuration
* malicious binaries and scripts

Because the attacker already obtained privileged configuration access, rebuilding WEB-01 from a trusted image is preferable to attempting to manually clean the system.

---

### 17.5.2 Windows Persistence

**Evidence:**

```text
09:40:02 - Service Created: SysUpdate
Image Path: C:\ProgramData\svchost.exe
```

and:

```text
20:00:04 - Service Created: SysUpdate
```

The service should be investigated and contained.

**Recommended actions:**

* Identify service creation time.
* Capture service configuration.
* Calculate executable hash.
* Acquire the executable for analysis.
* Identify service account.
* Determine parent process and creator.
* Remove the service after evidence preservation.
* Search all Windows hosts for SysUpdate.
* Search for `C:\ProgramData\svchost.exe` and matching hashes.

The legitimate Windows `svchost.exe` normally resides under the Windows system directory. An executable using that name from `C:\ProgramData\` therefore requires immediate investigation.

---

## 17.6 Web Application Remediation

**Evidence:**

```text
09:00:00 - GET /wp-login.php
09:00:01–09:00:34 - POST /wp-login.php
09:00:35 - GET /wp-admin/
09:00:36 - POST /admin-ajax.php
```

and:

```text
09:06:00 - GET /shell.php
09:06:01 - POST /shell.php
```

The WordPress environment should be treated as compromised.

**Recommended remediation:**

* Remove the affected server from production.
* Preserve the compromised instance for forensic analysis.
* Rebuild from a trusted operating-system image.
* Reinstall WordPress from verified sources.
* Update WordPress core, plugins and themes.
* Remove unauthorized plugins/themes/files.
* Review upload directories for executable content.
* Prevent PHP execution in user-uploadable directories where operationally appropriate.
* Replace exposed application secrets.
* Review WordPress administrator accounts.
* Implement MFA for administrative access.
* Restrict `/wp-admin/` access where possible.
* Implement rate limiting and authentication monitoring for `/wp-login.php`.

A simple deletion of `shell.php` is insufficient because the attacker may have established additional persistence.

---

## 17.7 Database Remediation

**Evidence:**

```text
09:30 - backup: SELECT customers, orders
09:35 - dbadmin: SELECT wp_users, UPDATE user_pass
```

The database requires integrity and confidentiality validation.

**Recommended actions:**

* Review database audit logs for all queries around the incident window.
* Identify all accounts that accessed `customers`, `orders`, and `wp_users`.
* Determine whether additional tables were accessed.
* Identify all authentication modifications.
* Validate database integrity.
* Rotate database credentials.
* Review application connection strings.
* Restrict database network access to authorized application hosts.
* Investigate whether database credentials existed in the exposed backup.

Where possible, compare affected tables against a known-good backup to identify unauthorized modifications.

---

## 17.8 Data Exposure Containment

**Evidence:**

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

The backup file should be considered potentially exposed.

**Immediate actions:**

* Remove the backup from public web-accessible storage.
* Determine why the file was located under the web-accessible upload path.
* Review web-server access controls.
* Search for other backup archives.
* Search for `.zip`, `.tar`, `.tar.gz`, `.sql`, `.bak`, configuration and credential files under web-accessible directories.
* Determine whether the backup contains credentials, customer data, database dumps or secrets.
* Rotate any credentials or secrets contained within it.

If external transfer can be confirmed through network telemetry, the organization should perform a formal data-exposure assessment based on the actual contents of the archive.

---

## 17.9 Network Containment

The following destination should be treated as an IOC:

```text
194.34.132.15:4444
```

Network investigation should identify:

* All internal hosts communicating with this destination
* First observed connection
* Last observed connection
* Connection frequency
* Transferred byte counts
* Other destinations contacted by the same processes
* Other hosts communicating with the same infrastructure

The investigation should also search for related infrastructure rather than relying exclusively on the single known IP address.

---

## 17.10 Investigation of Lateral Movement

The available evidence establishes suspicious activity on multiple systems but does not fully prove the exact transition path.

The investigation should therefore search for authentication and network relationships between:

```text
WEB-01
   ↓ ?
PC-MANAGER
   ↓ ?
DC-01
```

Priority telemetry includes:

* Windows Event IDs 4624/4625
* Event ID 4672
* Event ID 4688
* Event ID 7045
* Sysmon process/network events
* SMB authentication
* RDP authentication
* WinRM
* WMI
* PowerShell logging
* Remote service creation

The goal is to establish the actual movement path rather than infer it from timestamps alone.

---

## 17.11 Backup Infrastructure Validation

**Evidence:**

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

This activity appears consistent with legitimate backup operations, but the backup infrastructure is sufficiently sensitive that it should be explicitly validated.

**Recommended actions:**

* Confirm 172.16.10.50 is an authorized Veeam component.
* Validate the Veeam account.
* Review Veeam administrative activity.
* Review backup-job history.
* Search for unauthorized restore operations.
* Search for deletion or modification of backups.
* Review authentication from compromised hosts.
* Verify that immutable/offline backups remain intact.

At present, there is no direct evidence in the supplied logs that BACKUP-01 was compromised.

---

## 17.12 Eradication Strategy

Given the scope of the observed compromise, eradication should follow a rebuild-first strategy for confirmed compromised systems.

### WEB-01

**Recommended:**

```text
Forensic acquisition → rebuild → patch → harden → restore validated application/data.
```

### PC-MANAGER

**Recommended:**

```text
Forensic acquisition → isolate → rebuild or EDR-validated eradication → credential rotation → restore.
```

### DC-01

Because the Domain Controller is involved, remediation requires a separate Active Directory recovery plan.

At minimum:

* Investigate domain persistence.
* Validate privileged accounts.
* Review domain-controller integrity.
* Investigate credential exposure.
* Assess KRBTGT and privileged credential compromise.
* Validate other domain controllers.
* Review Group Policy.
* Search for unauthorized accounts and services.

If evidence establishes domain-wide credential compromise, the organization should follow its established Active Directory compromise recovery procedure rather than treating DC-01 as an ordinary infected endpoint.

---

## 17.13 Detection Engineering Improvements

The incident provides several high-value detection opportunities.

### Detection 1 — Suspicious Web Login Burst

Detect repeated authentication attempts against:

```text
/wp-login.php
```

combined with subsequent:

```text
/wp-admin/
/admin-ajax.php
```

within a short interval.

---

### Detection 2 — Public Backup Retrieval

Detect requests for sensitive archive extensions from web-accessible directories:

```text
.tar
.tar.gz
.zip
.bak
.sql
```

especially when the same source repeatedly retrieves the same large object.

---

### Detection 3 — Suspicious Service Creation

Detect:

```text
EventCode=7045
```

when the service executable is located in unusual writable directories such as:

```text
C:\ProgramData\
C:\Users\Public\
C:\Temp\
```

---

### Detection 4 — Encoded PowerShell + External Connection

Correlate:

```text
4688
PowerShell -Enc
```

with:

```text
7045
Service Creation
```

and:

```text
5156
External Network Connection
```

This correlation is substantially stronger than alerting on any one event independently.

---

## 17.14 Recovery Validation

Before returning affected systems to production, the SOC/IR team should validate:

* No known malicious processes remain.
* No unauthorized services remain.
* No unauthorized scheduled tasks remain.
* No suspicious SSH keys remain.
* sudoers configuration is clean.
* WordPress administrator accounts are validated.
* Database integrity is confirmed.
* Exposed credentials have been rotated.
* C2 destinations are blocked.
* EDR telemetry is operational.
* SIEM ingestion is complete.
* Monitoring rules are active.
* Network segmentation is functioning.
* Backups are verified and trustworthy.

For DC-01, additional Active Directory validation is mandatory before declaring the domain recovered.

---

## 17.15 Priority of Remediation

| Priority  | Action                                                      | Reason                                               |
| --------- | ----------------------------------------------------------- | ---------------------------------------------------- |
| Immediate | Isolate WEB-01, PC-MANAGER, and assess containment of DC-01 | Prevent continued attacker activity                  |
| Immediate | Block 194.34.132.15:4444                                    | Disrupt known C2                                     |
| Immediate | Preserve forensic evidence                                  | Prevent loss of investigative evidence               |
| Immediate | Protect/rotate compromised credentials                      | Prevent continued authentication                     |
| High      | Investigate SysUpdate                                       | Confirm/remove Windows persistence                   |
| High      | Remove public access to backup.tar.gz                       | Prevent continued data exposure                      |
| High      | Rebuild WEB-01                                              | Host integrity cannot be trusted                     |
| High      | Investigate Active Directory                                | DC compromise creates domain-level risk              |
| High      | Audit database access and modifications                     | Determine confidentiality/integrity impact           |
| Medium    | Validate BACKUP-01                                          | Determine whether backup infrastructure was affected |
| Medium    | Implement detection rules                                   | Prevent recurrence and improve visibility            |
| Medium    | Harden WordPress and administrative access                  | Reduce recurrence risk                               |

---

## 17.16 Containment and Remediation Conclusion

The appropriate response is not to clean individual indicators and return the systems to service.

The evidence demonstrates multiple persistence mechanisms:

```text
WEB-01
→ /etc/sudoers modification
→ shell.php
```

and:

```text
PC-MANAGER / DC-01
→ SysUpdate
→ C:\ProgramData\svchost.exe
→ 194.34.132.15:4444
```

Combined with:

```text
wp_users → UPDATE user_pass
```

and repeated:

```text
GET /backup.tar.gz
```

the incident must be handled as a multi-stage compromise with credential, persistence, command-and-control, and potential data-exposure consequences.

The preferred remediation outcome is therefore:

```text
Contain
    →
Preserve Evidence
    →
Determine Scope
    →
Eradicate Persistence
    →
Rotate Credentials
    →
Rebuild Untrusted Hosts
    →
Validate Active Directory
    →
Restore from Trusted Sources
    →
Deploy Detection Improvements
    →
Monitor for Recurrence
```

The incident should remain open until the organization can establish with reasonable confidence that attacker access has been removed, persistence has been eradicated, exposed credentials have been invalidated, affected systems have been restored to a trusted state, and no additional compromised hosts remain within the environment.
