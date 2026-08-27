# 9. Command-and-Control Activity

## 9.1 Overview

The available evidence identifies `194.34.132.15:4444` as the primary suspected Command-and-Control (C2) endpoint associated with the compromise.

The C2 assessment is not based on port 4444 alone. Port numbers are not reliable indicators of maliciousness by themselves. The determination is based on the correlation of the destination, process, timing, persistence mechanism, and preceding execution activity.

The strongest evidence originates from PC-MANAGER and DC-01, where the same externally routable IP address is contacted by a suspicious executable immediately after encoded PowerShell execution and creation of a service named SysUpdate.

---

## 9.2 C2 Establishment on PC-MANAGER

Relevant log evidence:

```text
09:40:00 - cmd.exe /c whoami
09:40:01 - PowerShell -Enc
09:40:02 - Service Created: SysUpdate
09:40:03 - svchost.exe → 194.34.132.15:4444
```

The sequence is significant because the network connection occurs immediately after execution and service creation.

`whoami` represents host/account discovery:

```text
09:40:00 - cmd.exe /c whoami
```

This is followed by encoded PowerShell:

```text
09:40:01 - PowerShell -Enc
```

and then creation of a service:

```text
09:40:02 - Service Created: SysUpdate
```

The newly created service subsequently communicates with:

```text
09:40:03 - svchost.exe → 194.34.132.15:4444
```

A legitimate service can communicate externally, and TCP/4444 is not inherently malicious. However, this sequence provides strong contextual evidence that the connection is associated with attacker-controlled execution rather than ordinary application traffic.

**Assessment:** High-confidence C2 activity.

---

## 9.3 Persistent C2 Communication

The connection was not an isolated network event.

Relevant log evidence:

```text
09:40:03 - svchost.exe → 194.34.132.15:4444
```

The surrounding evidence indicates that this connection pattern continued during the established malicious session.

A similar sequence appears later:

```text
11:00:00 - Logon Type 10
11:00:01 - 4672
11:00:02 - cmd /c whoami
11:00:03 - PowerShell -Enc
11:00:04 - Service Created: SysUpdate
11:00:05 onward - 5156 to 194.34.132.15:4444 (56 events)
```

The repeated connections following creation of the same suspicious service substantially strengthen the C2 assessment.

The important analytical point is that 56 Windows Filtering Platform connection events do not necessarily represent 56 separate C2 sessions. They demonstrate repeated permitted network connections/events associated with the process, but the supplied logs do not provide enough network-session metadata to determine exact session boundaries or transferred volume.

**Assessment:** Confirmed repeated communication with the suspected C2 infrastructure.

---

## 9.4 C2 Endpoint Consistency

The same external endpoint appears repeatedly throughout the incident.

Relevant log evidence:

```text
11:00:05 onward - 5156 to 194.34.132.15:4444 (56 events)
```

The endpoint is:

```text
Destination IP: 194.34.132.15
Destination Port: 4444
Protocol: TCP
```

The recurrence of the same destination after malicious process creation is an important indicator of infrastructure reuse.

The evidence therefore supports treating:

```text
194.34.132.15
TCP/4444
```

as a primary C2 IOC for this investigation.

It should not be described as malicious solely because it uses port 4444; the malicious assessment comes from its correlation with the surrounding execution and persistence evidence.

---

## 9.5 C2 Activity on DC-01

The same infrastructure was subsequently contacted from the Domain Controller.

Relevant log evidence:

```text
20:00:00 - 4624 Logon Type 10, User: maryam
20:00:01 - 4672
20:00:02 - cmd /c whoami
20:00:03 - PowerShell -Enc
20:00:04 - Service Created: SysUpdate
20:00:05 - C2 Connection to 194.34.132.15:4444 (60 events)
```

This is one of the most significant findings in the incident.

The activity on DC-01 reproduces the same behavioral sequence previously observed on PC-MANAGER:

```text
Privileged logon
      ↓
whoami
      ↓
Encoded PowerShell
      ↓
SysUpdate service creation
      ↓
Connection to 194.34.132.15:4444
```

The reuse of the same service name and external destination across hosts is strong evidence of common attacker tooling or a repeated intrusion procedure.

Because the affected system is a Domain Controller, the C2 activity has substantially greater incident significance than the equivalent activity on a standard workstation.

**Assessment:** Confirmed high-severity C2 activity on DC-01.

---

## 9.6 Process-to-Network Correlation

The process responsible for the observed outbound connection on PC-MANAGER was:

```text
09:40:03 - svchost.exe → 194.34.132.15:4444
```

This is significant because the executable was not simply observed communicating with the Internet in isolation. It appeared immediately after:

```text
09:40:02 - Service Created: SysUpdate
```

with the service image identified as:

```text
C:\ProgramData\svchost.exe
```

The combination of an executable located under C:\ProgramData, a service named SysUpdate, and outbound communication to the same external endpoint creates a strong process-to-network correlation.

A legitimate Windows svchost.exe normally resides under the Windows system directory. The supplied evidence instead identifies:

```text
C:\ProgramData\svchost.exe
```

which is materially suspicious.

**Assessment:** Strong evidence of a malicious service/process communicating with external C2 infrastructure.

---

## 9.7 C2 Activity Following Encoded PowerShell

Encoded PowerShell appears immediately before the C2 connection.

Relevant log evidence:

```text
09:40:01 - PowerShell -Enc
09:40:02 - Service Created: SysUpdate
09:40:03 - svchost.exe → 194.34.132.15:4444
```

The same pattern occurs on DC-01:

```text
20:00:03 - PowerShell -Enc
20:00:04 - Service Created: SysUpdate
20:00:05 - C2 Connection to 194.34.132.15:4444
```

Encoded PowerShell is not inherently malicious. Administrators and legitimate software can use encoded commands.

In this case, however, it occurs inside an already established malicious sequence and is followed by creation of a suspicious service and outbound communication to the same external endpoint.

This correlation substantially increases the confidence that the PowerShell activity was part of the malware deployment and C2 establishment process.

**Assessment:** High-confidence malicious PowerShell-to-C2 correlation.

---

## 9.8 C2 Relationship to the Web Compromise

The earlier compromise of WEB-01 provides important context for the later C2 activity.

Relevant log evidence:

```text
09:05:10 - wget update.sh
09:05:15 - downloading secondary payload
09:05:20 - bash /tmp/update.sh
```

The attacker first retrieved and executed additional tooling on the web server.

The subsequent web-shell activity was:

```text
09:06:00 - GET /shell.php
09:06:01 - POST /shell.php
```

Later, the suspected C2 infrastructure appears in host-level activity:

```text
09:40:03 - svchost.exe → 194.34.132.15:4444
```

and again:

```text
11:00:05 onward - 5156 to 194.34.132.15:4444
```

The supplied evidence therefore supports a broader intrusion pattern in which attacker access to the web environment is followed by payload execution and establishment of outbound communications from compromised Windows hosts.

However, the logs provided do not directly prove that 194.34.132.15 was the same infrastructure responsible for the initial compromise of WEB-01. The relationship is strongly suggested by the overall attack chain, but direct infrastructure attribution would require additional DNS, proxy, firewall, malware, or network-flow evidence.

**Assessment:** Strong correlation; direct causal attribution to the initial WEB-01 compromise remains unconfirmed.

---

## 9.9 C2 Persistence Across Multiple Hosts

The same C2 endpoint is observed in at least two compromised Windows systems.

### PC-MANAGER

```text
09:40:03 - svchost.exe → 194.34.132.15:4444
```

### PC-MANAGER — later activity

```text
11:00:05 onward - 5156 to 194.34.132.15:4444 (56 events)
```

### DC-01

```text
20:00:05 - C2 Connection to 194.34.132.15:4444 (60 events)
```

The recurrence across hosts indicates that the endpoint was not merely contacted by a single isolated process.

The reuse of:

```text
194.34.132.15:4444
```

across PC-MANAGER and DC-01 is consistent with centralized attacker infrastructure or a common payload configuration.

This is particularly important from a SOC perspective because the endpoint should be hunted across the entire environment rather than investigated only on the original compromised host.

**Assessment:** High-confidence shared C2 infrastructure indicator.

---

## 9.10 C2 and Lateral Movement Implications

The appearance of the same C2 infrastructure on PC-MANAGER and subsequently on DC-01 is consistent with an attacker progressing through the environment.

Relevant log evidence:

```text
PC-MANAGER
09:40:02 - Service Created: SysUpdate
09:40:03 - svchost.exe → 194.34.132.15:4444
```

Later:

```text
DC-01
20:00:00 - 4624 Logon Type 10, User: maryam
20:00:03 - PowerShell -Enc
20:00:04 - Service Created: SysUpdate
20:00:05 - C2 Connection to 194.34.132.15:4444
```

This does not, by itself, prove the exact lateral-movement mechanism.

For example, the supplied evidence does not contain sufficient information to state whether the attacker used RDP, SMB, stolen credentials, remote service execution, or another mechanism to move from PC-MANAGER to DC-01.

What can be stated with confidence is that the same malicious execution/C2 pattern eventually appeared on the Domain Controller.

**Assessment:** Strong evidence of compromise propagation; exact lateral-movement mechanism remains undetermined.

---

## 9.11 C2 Infrastructure Assessment

Based strictly on the supplied evidence, the following IOC has the highest confidence:

```text
IOC Type: External IPv4
Address: 194.34.132.15
Port: TCP/4444
Role: Suspected C2 infrastructure
Associated Hosts: PC-MANAGER, DC-01
Associated Process: C:\ProgramData\svchost.exe
Associated Persistence: SysUpdate service
```

The confidence derives from the following correlation:

```text
Encoded PowerShell
        +
Suspicious service creation
        +
C:\ProgramData\svchost.exe
        +
Repeated outbound TCP connections
        +
Same external destination
        +
Presence on multiple compromised hosts
```

No single one of these indicators is sufficient on its own to prove C2. Their temporal and behavioral correlation provides the basis for the high-confidence assessment.

---

## 9.12 Final Assessment

The supplied evidence supports a high-confidence determination that 194.34.132.15:4444 functioned as Command-and-Control infrastructure during the compromise.

The strongest evidence is the repeated sequence on PC-MANAGER and DC-01:

```text
User session
    ↓
whoami
    ↓
Encoded PowerShell
    ↓
SysUpdate service creation
    ↓
C:\ProgramData\svchost.exe
    ↓
194.34.132.15:4444
    ↓
Repeated outbound connections
```

The evidence establishes:

* Repeated outbound communication with 194.34.132.15:4444.
* Communication associated with a suspicious executable under C:\ProgramData.
* Communication immediately following encoded PowerShell execution.
* Communication immediately following creation of the SysUpdate service.
* Reuse of the same C2 endpoint across PC-MANAGER and DC-01.
* Continued C2 activity after persistence was established.
* C2 activity ultimately reaching a Domain Controller.

The evidence does not establish:

* The exact C2 protocol or application-layer protocol.
* The precise commands exchanged with the remote server.
* The amount of data transmitted to or from the C2 server.
* The exact mechanism used to move from PC-MANAGER to DC-01.
* That TCP/4444 itself is malicious.
* That 194.34.132.15 was definitively the initial-access infrastructure.

**Incident conclusion:** 194.34.132.15:4444 should be treated as a high-confidence C2 IOC and investigated across all available DNS, proxy, firewall, EDR, Windows Filtering Platform, and network-flow telemetry. Its appearance on DC-01 materially elevates the incident from a workstation compromise to a potential domain-level compromise.
