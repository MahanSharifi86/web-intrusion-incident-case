# 01 — Scenario and Raw Logs

## Purpose

This section contains the original training scenario and the raw telemetry used as the primary evidence source for the investigation.

The objective is to preserve the evidence in its original form and maintain a clear separation between **raw observations** and subsequent analytical conclusions.

No incident conclusion should be derived from this document in isolation. Individual events must be correlated with other available telemetry and evaluated within their temporal and host context.

---

## Scenario

The simulated environment represents a small enterprise network containing web application infrastructure, user workstations, a database system, a domain controller, and backup infrastructure.

During the investigation window, multiple security-relevant events were observed across the environment, including:

- Repeated authentication attempts against a WordPress login endpoint.
- Successful access to the WordPress administrative interface.
- Repeated retrieval of a backup archive.
- SSH access to the web server using the `www-data` account.
- Command execution and payload retrieval.
- Modification of host security controls.
- Web shell activity.
- Changes to local privilege configuration.
- Suspicious privileged activity on `PC-MANAGER`.
- Encoded PowerShell execution.
- Creation of a Windows service named `SysUpdate`.
- Repeated outbound connections to an external address over TCP/4444.
- Database activity involving WordPress authentication data.
- Subsequent suspicious activity involving `DC-01`.

The investigation is intended to determine whether these events form a single intrusion chain, identify the affected assets, establish the most defensible sequence of attacker activity, and distinguish confirmed findings from hypotheses that require additional evidence.

---

## Investigation Window

The available evidence spans multiple stages of activity throughout the investigation period, beginning with early authentication and administrative activity and continuing through subsequent host compromise, command-and-control communication, database activity, and activity involving the domain controller and backup infrastructure.

All timestamps are preserved as provided in the source telemetry.

---

## Environment

The simulated environment contains the following relevant assets:

| Asset | Role | Relevance |
|---|---|---|
| `WEB-01` | Web Server | Primary web application attack surface |
| `PC-MANAGER` | User Workstation | User activity and subsequent suspicious execution |
| `DB-01` | Database Server | Database and authentication-data activity |
| `DC-01` | Domain Controller | Authentication, privileged activity, and suspected lateral movement |
| `BACKUP-01` | Backup Server | Backup-related activity observed during the investigation |

---

## Primary Accounts Observed

The following accounts appear in the available telemetry:

| Account | Context |
|---|---|
| `deploy` | Administrative activity on `WEB-01` |
| `webadmin` | Web server administrative activity |
| `jenkins` | Service/deployment-related account |
| `maryam` | User account associated with `PC-MANAGER` and subsequent privileged activity |
| `www-data` | Web server service account observed during SSH activity |
| `dbadmin` | Database administrative account |
| `Veeam` | Backup-related account |

The presence of an account in the telemetry does not, by itself, establish that the account was compromised.

---

## External Indicators Observed

The raw telemetry contains the following external network indicators:

| Indicator | Observed Context |
|---|---|
| `45.33.22.11` | Source of repeated WordPress authentication activity and subsequent SSH access |
| `194.34.132.15` | Destination of repeated outbound TCP connections from `C:\ProgramData\svchost.exe` |
| `194.34.132.15:4444` | Repeated outbound connection observed in Windows filtering telemetry |

These indicators are preserved here as observations. Their malicious classification is established only through correlation with associated behavior in the investigation.

---

## Evidence Handling Principles

The raw logs in this section are treated as **source evidence** for the case.

The investigation follows these principles:

### Evidence Preservation

Raw telemetry is retained without adding analytical conclusions to individual events.

### Source-to-Finding Traceability

Significant findings documented elsewhere in the repository should be traceable back to specific raw events.

### Temporal Correlation

Events are evaluated according to their timestamps and sequence rather than as isolated indicators.

### Cross-Host Correlation

Authentication, process execution, network activity, web requests, and database events are correlated across affected systems.

### Fact and Hypothesis Separation

The investigation distinguishes between:

- **Observed:** directly present in the telemetry.
- **Assessed:** a conclusion supported by multiple observations.
- **Unconfirmed:** a plausible explanation that cannot be established with the available evidence.

---

## Raw Evidence

The complete telemetry associated with this scenario is preserved in:

`raw-logs.txt`

The file contains the raw log material supplied for the investigation, including web server, authentication, Windows Security, process, service, network, and database-related events.

---

## Analytical Boundary

This directory is intentionally separated from the analytical sections of the case.

The raw evidence should not be modified to reflect later conclusions. Any interpretation, classification, timeline reconstruction, MITRE ATT&CK mapping, or attribution assessment belongs in the corresponding investigation section.

This separation ensures that the analytical conclusions can be independently reviewed against the underlying evidence.

---

## Related Investigation Sections

The evidence contained in this directory is analyzed throughout the case, including:

- [Incident Scope and Affected Assets](../03-Incident-Analysis/01-Incident-Scope-and-Affected-Assets.md)
- [Evidence Summary](../03-Incident-Analysis/02-Evidence-Summary.md)
- [Confirmed Attack Timeline](../03-Incident-Analysis/03-Confirmed-Attack-Timeline.md)
- [Initial Access Assessment](../03-Incident-Analysis/04-Initial-Access-Assessment.md)
- [WEB-01 Compromise](../03-Incident-Analysis/05-WEB-01-Compromise.md)
- [Web Shell and Persistence](../03-Incident-Analysis/06-Web-Shell-and-Persistence.md)
- [Credential and Account Compromise](../03-Incident-Analysis/07-Credential-and-Account-Compromise.md)
- [Command-and-Control Activity](../03-Incident-Analysis/08-Command-and-Control-Activity.md)
- [Lateral Movement](../03-Incident-Analysis/09-Lateral-Movement.md)
- [Data Access and Potential Exfiltration](../03-Incident-Analysis/10-Data-Access-and-Potential-Exfiltration.md)
- [Attack Chain Reconstruction](../03-Incident-Analysis/11-Attack-Chain-Reconstruction.md)
- [MITRE ATT&CK Mapping](../03-Incident-Analysis/12-MITRE-ATT&CK-Mapping.md)
- [Indicators of Compromise](../03-Incident-Analysis/13-Indicators-of-Compromise.md)
- [Impact Assessment](../03-Incident-Analysis/14-Impact-Assessment.md)
- [Evidence Gaps and Unconfirmed Findings](../03-Incident-Analysis/15-Evidence-Gaps-and-Unconfirmed-Findings.md)
- [Containment and Remediation Recommendations](../03-Incident-Analysis/16-Containment-and-Remediation-Recommendations.md)
- [Final Incident Assessment](../03-Incident-Analysis/17-Final-Incident-Assessment.md)

---

## Disclaimer

This is a simulated incident-response scenario created for defensive security training, SOC investigation, threat hunting, and incident-response analysis.

The systems, accounts, domains, IP addresses, and observed activities represented in the dataset belong to the simulated training environment.
