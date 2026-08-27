# 10. Lateral Movement to PC-MANAGER and DC-01

## 10.1 Assessment

The available evidence supports post-compromise access to PC-MANAGER and subsequent activity on DC-01, but it does not independently establish the exact mechanism used to move between systems.

The activity observed on PC-MANAGER and DC-01 is strongly correlated with the previously identified compromise of WEB-01. However, the available logs do not provide sufficient network or authentication telemetry to conclusively identify whether the attacker used stolen credentials, Remote Desktop Protocol (RDP), SMB, a remote service, or another lateral-movement mechanism.

Accordingly, this section distinguishes between confirmed host activity and the unconfirmed movement path.

---

## 10.2 PC-MANAGER Access

The first relevant authentication evidence is:

```text
2025-06-10 08:07:00
4624 Logon Type 10
User: maryam
Source IP: 192.168.1.100
```

This is a Windows Remote Interactive Logon (Logon Type 10), which is commonly associated with RDP-based interactive sessions.

A privileged token was subsequently assigned:

```text
2025-06-10 08:07:01
4672 Special Privileges
User: maryam
```

The combination of Event ID 4624, Logon Type 10, followed immediately by Event ID 4672 establishes that a privileged interactive session for maryam was created.

However, the source address requires caution:

```text
Source IP: 192.168.1.100
```

The available evidence does not establish that 192.168.1.100 represents a separate attacking workstation. Therefore, the following conclusion cannot be made from these events alone:

> "An external attacker remotely connected to PC-MANAGER."

The defensible conclusion is:

> A privileged Remote Interactive session associated with the maryam account was established on PC-MANAGER, but the originating system and exact lateral-movement mechanism cannot be conclusively determined from the available authentication event alone.

---

## 10.3 PC-MANAGER Post-Authentication Activity

The authentication event is followed by process creation:

```text
2025-06-10 08:07:01
4672 Special Privileges
User: maryam
```

and subsequently:

```text
2025-06-10 08:08:00
Chrome LOG:
https://tosnet.ir/wp-admin/
```

This establishes that the maryam session was followed by browser activity involving the organization's WordPress administration interface.

The more significant evidence appears later on the same host:

```text
2025-06-10 09:40:00
cmd.exe /c whoami
```

```text
2025-06-10 09:40:01
PowerShell -Enc
```

```text
2025-06-10 09:40:02
Service Created: SysUpdate
```

```text
2025-06-10 09:40:03
svchost.exe → 194.34.132.15:4444
```

This sequence is materially different from ordinary administrative activity.

The execution of:

```text
cmd.exe /c whoami
```

is consistent with determining the security context of the current process.

It is immediately followed by:

```text
PowerShell -Enc
```

which indicates execution of an encoded PowerShell command.

The sequence then progresses to:

```text
Service Created: SysUpdate
```

followed by an outbound connection:

```text
svchost.exe → 194.34.132.15:4444
```

Taken together, these events provide strong evidence that PC-MANAGER was compromised and subsequently used to establish persistence and outbound command-and-control communication.

The evidence does not, however, prove that the compromise originated from WEB-01.

---

## 10.4 DC-01 Access

The strongest evidence of subsequent access to the domain controller occurs at 20:00:

```text
2025-06-10 20:00:00
DC-01
Security Event 4624
Logon Type 10
User: maryam
Source IP: 192.168.1.100
```

This is followed one second later by:

```text
2025-06-10 20:00:01
DC-01
Security Event 4672
Special Privileges
User: maryam
```

The session was then followed by command execution:

```text
2025-06-10 20:00:02
DC-01
Security Event 4688
Process Create
Image: C:\Windows\System32\cmd.exe
Command: cmd.exe /c whoami
Parent: explorer.exe
```

Immediately afterward:

```text
2025-06-10 20:00:03
DC-01
Security Event 4688
Process Create
Image: C:\Windows\System32\powershell.exe
Command: powershell.exe -Enc ...
Parent: cmd.exe
```

The persistence mechanism was then created:

```text
2025-06-10 20:00:04
DC-01
Security Event 7045
Service Created
Service Name: SysUpdate
Image Path: C:\ProgramData\svchost.exe
Start Type: Auto
```

Finally, the newly created executable established outbound communication:

```text
2025-06-10 20:00:05 onward
DC-01
Security Event 5156
Process: C:\ProgramData\svchost.exe
Destination: 194.34.132.15:4444
Protocol: TCP
Action: Allow
```

The subsequent 5156 events continue through:

```text
20:01:00
```

This sequence provides strong evidence that DC-01 was compromised and that malicious execution and persistence occurred after the maryam interactive session.

---

## 10.5 Relationship Between PC-MANAGER and DC-01

A significant correlation exists between the two hosts.

### PC-MANAGER

```text
4624 Type 10 → 4672 → cmd.exe → PowerShell -Enc
→ SysUpdate service → 194.34.132.15:4444
```

### DC-01

```text
4624 Type 10 → 4672 → cmd.exe → PowerShell -Enc
→ SysUpdate service → 194.34.132.15:4444
```

The same operational sequence appears on both systems.

This is highly significant because the probability that the complete sequence represents unrelated legitimate administrative activity on both hosts is low, particularly when the sequence includes:

```text
Service Name: SysUpdate
Image Path: C:\ProgramData\svchost.exe
```

and:

```text
Destination: 194.34.132.15:4444
```

The repeated use of the same service name, executable location, encoded PowerShell execution, and external destination establishes a strong behavioral relationship between the two compromises.

---

## 10.6 What Can Be Confirmed

Based strictly on the available evidence, the following findings are supported:

| Finding                                                          | Assessment                                 |
| ---------------------------------------------------------------- | ------------------------------------------ |
| maryam had a Type 10 interactive logon on PC-MANAGER             | Confirmed                                  |
| maryam received special privileges on PC-MANAGER                 | Confirmed                                  |
| Suspicious command execution occurred on PC-MANAGER              | Confirmed                                  |
| Encoded PowerShell executed on PC-MANAGER                        | Confirmed                                  |
| SysUpdate persistence was created on PC-MANAGER                  | Confirmed                                  |
| PC-MANAGER communicated with 194.34.132.15:4444                  | Confirmed                                  |
| maryam had a Type 10 interactive logon on DC-01                  | Confirmed                                  |
| maryam received special privileges on DC-01                      | Confirmed                                  |
| Suspicious command execution occurred on DC-01                   | Confirmed                                  |
| Encoded PowerShell executed on DC-01                             | Confirmed                                  |
| SysUpdate persistence was created on DC-01                       | Confirmed                                  |
| DC-01 communicated with 194.34.132.15:4444                       | Confirmed                                  |
| PC-MANAGER → DC-01 lateral movement                              | Highly likely, but mechanism not confirmed |
| RDP was definitely the movement mechanism                        | Not confirmed                              |
| WEB-01 directly moved to PC-MANAGER                              | Not confirmed                              |
| 192.168.1.100 is definitively the attacker's originating machine | Not established                            |

---

## 10.7 Lateral Movement Assessment

The evidence therefore supports the following incident model:

```text
WEB-01
   |
   | Compromise established
   |
   v
PC-MANAGER
   |
   | Privileged interactive session
   | cmd.exe
   | PowerShell -Enc
   | SysUpdate
   | C2: 194.34.132.15:4444
   |
   v
DC-01
   |
   | Privileged interactive session
   | cmd.exe
   | PowerShell -Enc
   | SysUpdate
   | C2: 194.34.132.15:4444
```

The host-to-host relationship is strongly supported, but the precise lateral-movement mechanism remains an investigative gap.

In particular, the evidence currently available does not include sufficient telemetry to distinguish between:

* compromised maryam credentials;
* RDP-based lateral movement;
* SMB/Windows administrative access;
* remote service execution;
* another credential-based remote-access mechanism.

Therefore, a professional incident report should not state "the attacker used RDP" as a confirmed fact merely because Event ID 4624 has Logon Type 10.

---

## 10.8 Investigative Gap

The next investigation should focus on determining how the attacker obtained or used the maryam credentials and how the session on PC-MANAGER relates to the subsequent DC-01 access.

The highest-value missing evidence would be:

1. Windows Security 4624/4625 records from both systems with complete source/destination context.
2. RDP Terminal Services logs to confirm or reject RDP usage.
3. SMB authentication and share-access logs to identify credential-based movement.
4. Process creation telemetry around the initial session.
5. Network telemetry between WEB-01, PC-MANAGER, and DC-01.
6. Credential-access indicators on WEB-01 and PC-MANAGER.
7. Active Directory authentication records to establish the exact sequence of account use.

Until those artifacts are obtained, the correct incident-response conclusion is:

> Lateral movement to PC-MANAGER and DC-01 is strongly indicated by correlated privileged interactive sessions and identical post-authentication execution patterns. The exact movement mechanism and originating host, however, remain unconfirmed.
