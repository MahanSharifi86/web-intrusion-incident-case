حتماً. با توجه به ساختار فعلی Repository تو، این نسخه را برای **`README.md` اصلی** بگذار. ساختار قبلی داخل README هنوز قدیمی است و باید با این نسخه جایگزین شود. ([GitHub][1])

````markdown
# Web Intrusion Incident Case

## Incident Response & Threat Hunting Investigation

This repository documents an evidence-driven investigation of a simulated multi-stage enterprise intrusion involving web application compromise, credential abuse, persistence, command-and-control activity, lateral movement, database access, and potential data exfiltration.

The investigation reconstructs the attack lifecycle from available telemetry and distinguishes confirmed observations from analytical assessments and unconfirmed hypotheses.

---

## Incident Overview

| Category | Assessment |
|---|---|
| Incident Type | Multi-Stage Enterprise Intrusion |
| Primary Attack Surface | Web Application / Web Server |
| Severity | Critical |
| Investigation Focus | SOC / Incident Response / Threat Hunting |
| Primary Affected Assets | WEB-01, PC-MANAGER, DC-01, DB-01 |
| Key External Infrastructure | 45.33.22.11, 194.34.132.15 |
| Primary Compromised Accounts | www-data, maryam, dbadmin |
| Primary C2 Indicator | 194.34.132.15:4444 |
| Investigation Approach | Evidence Correlation & Attack Chain Reconstruction |
| Assessment Status | Based on Available Telemetry |

---

## Investigation Objectives

The investigation aims to determine:

- The most likely initial access vector.
- The sequence of attacker activity across affected systems.
- Whether WEB-01 was successfully compromised.
- Whether persistence mechanisms were established.
- Whether credentials were compromised or abused.
- Whether lateral movement occurred.
- The nature and significance of command-and-control activity.
- What sensitive data was accessed.
- Whether data exfiltration can be confirmed from the available evidence.
- The operational impact of the intrusion.
- Which findings are confirmed and which remain unconfirmed due to evidence gaps.
- Appropriate containment and remediation actions.

---

## Key Findings

The available evidence indicates a multi-stage compromise involving:

- Repeated authentication attempts against the WordPress login interface.
- Successful access to the WordPress administrative interface.
- Repeated retrieval of `backup.tar.gz`.
- Host-level access through the `www-data` account.
- Payload retrieval and execution on WEB-01.
- Modification of host security controls and filesystem permissions.
- Deployment and subsequent use of a web shell.
- Persistence through modification of `sudoers`.
- Suspicious privileged activity on PC-MANAGER.
- Encoded PowerShell execution.
- Creation of the `SysUpdate` service.
- Repeated outbound connections to `194.34.132.15:4444`.
- Database activity involving WordPress authentication data.
- Subsequent suspicious activity on DC-01.
- Evidence consistent with lateral movement and expansion of the compromise.
- Repeated access to potentially sensitive backup data.

Findings are assessed according to the strength of the available evidence rather than solely on behavioral assumptions.

---

## Investigation Methodology

The investigation follows an evidence-driven incident-response methodology:

1. **Evidence Collection**
2. **Event Correlation**
3. **Timeline Reconstruction**
4. **Host and Account Analysis**
5. **Attack Chain Reconstruction**
6. **MITRE ATT&CK Mapping**
7. **Impact Assessment**
8. **Evidence Gap Identification**
9. **Containment and Remediation Planning**
10. **Final Incident Assessment**

Where possible, every significant assessment is supported by the corresponding log evidence.

---

## Evidence Sources

The case incorporates multiple telemetry sources, including:

- Nginx access logs
- Linux authentication logs
- Sudo activity
- Windows Security Event Logs
- Process creation events
- Service creation events
- Windows Filtering Platform events
- Database activity
- Web application activity
- Network connection telemetry
- Authentication events

---

## Repository Structure

```text
web-intrusion-incident-case/
│
├── README.md
│
├── 01-Scenario-and-Raw-Logs/
│   ├── README.md
│   └── raw-logs.txt
│
└── 02-Incident-Report/
    └── README.md
````

### `01-Scenario-and-Raw-Logs`

Contains the original simulated scenario and raw telemetry used as the evidence base for the investigation.

The raw logs are intentionally preserved separately from analytical conclusions to maintain a clear distinction between source evidence and analyst assessment.

### `02-Incident-Report`

Contains the complete incident response case file, including the full investigation, attack timeline, compromise analysis, attack-chain reconstruction, MITRE ATT&CK mapping, impact assessment, evidence gaps, and remediation recommendations.

---

## Analytical Principles

This investigation follows several core principles used in professional incident response.

### Evidence Before Attribution

Conclusions are based on observed telemetry and correlated evidence.

Suspicious behavior is not automatically treated as confirmed malicious activity without supporting evidence.

### Fact, Assessment, and Hypothesis Separation

Findings are distinguished between:

* **Observed Evidence** — directly supported by telemetry.
* **Analytical Assessment** — conclusions derived from correlated evidence.
* **Unconfirmed Hypothesis** — plausible explanations requiring additional evidence.

### Timeline-Based Analysis

Individual events are evaluated within their temporal context to identify relationships between authentication, execution, persistence, lateral movement, C2 activity, and data access.

### Cross-Host Correlation

Events are correlated across multiple assets rather than investigated in isolation to reconstruct the broader intrusion path.

---

## Primary Investigation Questions

The case focuses on three central questions:

### 1. Where Did the Intrusion Begin?

Determine the most defensible initial access hypothesis based on the available authentication, web application, and host telemetry.

### 2. How Did the Compromise Propagate?

Establish the relationship between `WEB-01`, `PC-MANAGER`, `DB-01`, and `DC-01`, including evidence of credential abuse, lateral movement, execution, and persistence.

### 3. Was Sensitive Data Exfiltrated?

Determine whether repeated access to `backup.tar.gz` represents confirmed data exfiltration or only evidence of repeated data retrieval, and identify what additional telemetry would be required for confirmation.

---

## MITRE ATT&CK

Observed attacker behaviors are mapped to relevant MITRE ATT&CK techniques where sufficient evidence exists.

The mapping prioritizes behavioral evidence over superficial indicators such as individual port numbers, process names, or isolated events.

The complete mapping is documented in the incident report.

---

## Analyst

**Mahan — Autherion**

Focus Areas:

* Security Operations
* Threat Hunting
* Incident Response
* Digital Forensics
* Log Analysis
* Detection Engineering
* MITRE ATT&CK
* Attack Chain Reconstruction

---

## Disclaimer

This repository contains a simulated incident-response scenario created for defensive security training, threat hunting, and SOC investigation practice.

The infrastructure, identities, IP addresses, domains, and attack activity represented in this repository are part of the simulated environment and should not be interpreted as evidence of a real-world incident.
