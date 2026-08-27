# Web Intrusion Incident Case

## Incident Response & Threat Hunting Investigation

This repository presents an evidence-driven investigation of a simulated multi-stage enterprise intrusion.

The case focuses on the identification, analysis, and reconstruction of attacker activity across a web server, user workstation, domain controller, and database infrastructure.

The investigation is based on available security telemetry and applies a structured incident-response methodology to distinguish confirmed findings from analytical assessments and unconfirmed hypotheses.

---

## Case Overview

| Category                    | Assessment                                         |
| --------------------------- | -------------------------------------------------- |
| Incident Type               | Multi-Stage Enterprise Intrusion                   |
| Primary Attack Surface      | Web Application / Web Server                       |
| Severity                    | Critical                                           |
| Investigation Focus         | Incident Response / Threat Hunting / SOC Analysis  |
| Primary Affected Assets     | WEB-01, PC-MANAGER, DC-01, DB-01                   |
| Key External Infrastructure | 45.33.22.11, 194.34.132.15                         |
| Primary C2 Indicator        | 194.34.132.15:4444                                 |
| Investigation Method        | Evidence Correlation & Attack Chain Reconstruction |
| Assessment Status           | Based on Available Telemetry                       |
| Environment                 | Simulated Enterprise Environment                   |

---

## Investigation Objectives

The investigation is intended to establish:

* The most defensible initial access assessment.
* The sequence of significant attacker activity.
* The compromise status of affected systems.
* Evidence of persistence and credential abuse.
* Evidence of lateral movement between systems.
* The nature of identified command-and-control activity.
* The scope of data access.
* Whether data exfiltration can be confirmed from the available telemetry.
* The overall impact of the intrusion.
* Evidence gaps that prevent definitive conclusions.
* Appropriate containment and remediation measures.

---

## Key Findings

The available telemetry is consistent with a multi-stage intrusion involving:

* Repeated authentication attempts against the WordPress login interface.
* Subsequent access to the WordPress administrative interface.
* Repeated retrieval of `backup.tar.gz`.
* Host-level activity under the `www-data` account.
* Retrieval and execution of a secondary payload on WEB-01.
* Modification of host security controls and filesystem permissions.
* Deployment and subsequent access to a web shell.
* Modification of `sudoers` to establish persistent privileged access.
* Suspicious privileged execution on PC-MANAGER.
* Encoded PowerShell execution.
* Creation of a service named `SysUpdate`.
* Repeated outbound connections to `194.34.132.15:4444`.
* Database activity involving WordPress authentication data.
* Subsequent suspicious activity on DC-01.
* Activity consistent with lateral movement and expansion of the compromise.
* Repeated access to potentially sensitive backup data.

The findings are evaluated according to the available evidence and its level of corroboration. Behavioral indicators are not treated as definitive proof of compromise without supporting telemetry.

---

## Evidence Model

The investigation maintains a distinction between three analytical levels:

### Observed Evidence

Events directly supported by available telemetry, such as authentication events, process execution, network connections, web requests, and database activity.

### Analytical Assessment

Conclusions derived from correlating multiple observed events across time, hosts, accounts, and telemetry sources.

### Unconfirmed Hypothesis

A plausible explanation that cannot be established conclusively using the available evidence and requires additional telemetry or validation.

This model is applied throughout the incident report to prevent unsupported attribution and overstatement of findings.

---

## Evidence Sources

The investigation uses the following telemetry categories:

* Nginx access logs
* Linux authentication logs
* Sudo activity
* Windows Security Event Logs
* Process creation telemetry
* Service creation telemetry
* Windows Filtering Platform events
* Database activity
* Web application activity
* Network connection telemetry
* Authentication events

The original scenario and raw telemetry are preserved separately from the analytical report.

---

## Investigation Approach

The investigation follows a structured workflow:

1. Review the available telemetry.
2. Identify significant security events.
3. Correlate events temporally and across hosts.
4. Validate relationships between accounts, systems, processes, and network activity.
5. Reconstruct the most defensible attack sequence.
6. Assess the level of compromise for affected assets.
7. Map confirmed attacker behaviors to MITRE ATT&CK where appropriate.
8. Identify evidence gaps and unresolved hypotheses.
9. Assess operational impact.
10. Develop containment and remediation recommendations.
11. Produce a final incident assessment.

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
```

### `01-Scenario-and-Raw-Logs`

Contains the simulated incident scenario and the raw telemetry used as the primary evidence base for the investigation.

Source evidence is intentionally maintained separately from analytical conclusions.

### `02-Incident-Report`

Contains the complete Incident Response Case File.

The report documents the significant findings, supporting evidence, confirmed attack timeline, initial access assessment, system compromise, persistence, credential abuse, command-and-control activity, lateral movement, data access, attack-chain reconstruction, MITRE ATT&CK mapping, indicators of compromise, impact, evidence gaps, and remediation recommendations.

---

## Analytical Principles

### Evidence-Driven Analysis

Significant conclusions are derived from available telemetry and cross-event correlation.

### Temporal Correlation

Events are evaluated within their chronological context to identify relationships between initial access, execution, persistence, credential abuse, lateral movement, C2 activity, and data access.

### Cross-Host Correlation

Activity is evaluated across affected systems rather than treating individual hosts or events in isolation.

### Conservative Attribution

The investigation avoids treating suspicious indicators as definitive evidence when alternative explanations remain plausible.

### Evidence Preservation

Raw telemetry is preserved separately from analytical conclusions to maintain a clear distinction between source evidence and investigator assessment.

---

## Primary Investigation Questions

The investigation addresses three primary questions:

### Initial Access

What is the most defensible explanation for how the intrusion initially gained access to the environment?

### Intrusion Propagation

How did the compromise progress from the initially affected system to PC-MANAGER, DB-01, and DC-01?

### Data Access and Exfiltration

What sensitive information was accessed, and does the available telemetry provide sufficient evidence to confirm external data exfiltration?

---

## MITRE ATT&CK

Relevant attacker behaviors are mapped to MITRE ATT&CK techniques where the available evidence provides sufficient support.

Technique selection is based on observed behavior and correlated telemetry rather than isolated indicators such as port numbers, process names, or filenames.

The complete ATT&CK mapping is documented in the Incident Response Case File.

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

This repository contains a simulated incident-response scenario created for defensive security training, SOC analysis, threat hunting, and incident-response practice.

The systems, identities, IP addresses, domains, credentials, and attack activity represented in this repository belong to the simulated environment and should not be interpreted as evidence of a real-world incident.
