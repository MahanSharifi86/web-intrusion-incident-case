# 8. Credential and Account Compromise

## 8.1 Overview

The available evidence indicates that multiple accounts were involved in the incident, but the evidence does not support treating all observed accounts as compromised with the same level of confidence.

The strongest evidence concerns the maryam account, which appears repeatedly in authentication and privileged-activity records across multiple systems and time periods. The www-data account on WEB-01 was also leveraged by the attacker and subsequently granted unrestricted passwordless sudo access. The dbadmin account was associated with a highly sensitive database modification involving WordPress credentials.

The evidence supports an assessment of credential abuse and account compromise, but the original mechanism by which the attacker obtained each credential cannot be conclusively established from the supplied logs alone.

---

## 8.2 maryam Account — Initial Suspicion

Relevant log evidence:

```text
08:07:00 - 4624 Logon Type 10, User: maryam, Source IP: 192.168.1.100
08:07:01 - 4672 Special Privileges, User: maryam
08:08:00 - Chrome LOG: https://tosnet.ir/wp-admin/
```

The maryam account generated a Remote Interactive (Logon Type 10) authentication event followed immediately by a 4672 Special Privileges event.

The 4672 event must not be interpreted as proof of privilege escalation. It indicates that the authenticated security token was assigned one or more sensitive privileges. Whether this represents normal administrative access or unauthorized privilege acquisition requires additional context.

The source IP is also significant:

```text
Source IP: 192.168.1.100
```

Because the source address is the same address associated with the host in the supplied evidence, the event alone cannot establish that an external attacker remotely accessed Mary's workstation.

The subsequent browser activity is consistent with access to the organization's WordPress administration interface:

```text
08:08:00 - Chrome LOG: https://tosnet.ir/wp-admin/
```

At this stage, therefore, the maryam account should be treated as suspicious but not yet proven compromised.

---

## 8.3 maryam Account — Reuse During the Attack

The evidence becomes substantially stronger when the same account appears in later activity associated with the established attack chain.

Relevant log evidence:

```text
09:20:00 - GET /wp-admin/
09:20:01 - POST /admin-ajax.php
09:20:02 - GET /backup.tar.gz (15 requests)
```

This activity alone does not prove credential compromise because the supplied web logs do not explicitly identify the authenticated account.

However, it is relevant when correlated with the later authentication evidence.

Relevant log evidence:

```text
11:00:00 - Logon Type 10
11:00:01 - 4672
11:00:02 - cmd /c whoami
11:00:03 - PowerShell -Enc
11:00:04 - Service Created: SysUpdate
```

The same sequence subsequently appears alongside persistent C2 activity:

```text
11:00:05 onward - 5156 to 194.34.132.15:4444
```

This establishes a strong correlation between an authenticated privileged session and activity that is independently assessed as malicious.

The important distinction is that Logon Type 10 does not itself indicate credential theft. The evidence establishes that the account was used in a malicious execution chain; it does not establish whether the attacker obtained the password, reused an existing session, obtained a token, or used another authentication mechanism.

**Assessment:** Strong evidence of unauthorized use of the maryam identity.

---

## 8.4 maryam Account — Continued Use After Logoff

A particularly important correlation occurs after the recorded logoff period.

Relevant log evidence:

```text
17:00 - Logoff events
```

Later:

```text
18:00:00 - GET /wp-admin/
18:00:01 - POST /admin-ajax.php
18:00:02 - GET /backup.tar.gz (100 requests)
```

The subsequent activity is significant because the same account-associated web activity resumes after the recorded logoff period.

However, the statement that this proves an attacker logged in using Mary's stolen credentials would exceed the available evidence. The supplied web logs do not contain sufficient authentication metadata to establish the exact authentication mechanism at 18:00.

The defensible conclusion is:

> The maryam identity continued to be associated with suspicious administrative web activity after a prior logoff event, raising a strong possibility of credential/session compromise.

Further authentication logs, Windows Security events, VPN/RDP records, or application audit logs would be required to establish the precise mechanism.

**Assessment:** High-confidence suspicious account reuse; credential theft mechanism not established.

---

## 8.5 maryam Account — Use on DC-01

The most severe evidence involving the account occurs on the Domain Controller.

Relevant log evidence:

```text
20:00:00 - 4624 Logon Type 10, User: maryam
20:00:01 - 4672
20:00:02 - cmd /c whoami
20:00:03 - PowerShell -Enc
20:00:04 - Service Created: SysUpdate
20:00:05 - C2 Connection to 194.34.132.15:4444
```

This sequence is materially different from an ordinary administrative login.

The account authenticates to DC-01, receives special privileges, executes cmd.exe, launches encoded PowerShell, creates a suspicious service, and establishes communication with the previously identified external C2 infrastructure.

The combination of these events provides strong evidence that the maryam identity was being used as part of the attack against the domain infrastructure.

Importantly, this does not prove that Maryam herself performed these actions. Account attribution and human attribution are separate questions.

**Assessment:** maryam should be treated as a compromised or unauthorizedly controlled account for incident-response purposes.

---

## 8.6 www-data Account — Host-Level Account Abuse

The attacker obtained access to WEB-01 using the www-data identity.

Relevant log evidence:

```text
09:05:00 - Accepted password for www-data from 45.33.22.11
09:05:01 - session opened
09:05:05 - whoami && hostname && ip a
```

This is significant because the authentication originates from the same external address associated with the preceding web attack:

```text
45.33.22.11
```

The subsequent activity demonstrates that the authenticated identity was being used interactively.

The attacker then modified the privilege configuration.

Relevant log evidence:

```text
09:05:40 - echo 'www-data ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
```

This changes the security properties of the www-data account by granting it unrestricted passwordless sudo.

The evidence therefore supports two conclusions:

1. www-data was successfully used by the attacker.
2. The attacker converted that account into a persistent administrative access path.

The logs do not establish whether the original www-data password was stolen, guessed, reused, or obtained through another mechanism.

**Assessment:** Confirmed compromise and privilege-persistence abuse of www-data.

---

## 8.7 dbadmin Account — Credential Modification Activity

The database evidence contains a separate high-impact account event.

Relevant log evidence:

```text
09:30 - backup: SELECT customers, orders
09:35 - dbadmin: SELECT wp_users, UPDATE user_pass
```

The dbadmin account accessed the WordPress user table and performed an update against the password field.

The significance is not merely that a database administrator executed a query. The operation directly targets authentication material associated with WordPress users.

The supplied evidence does not establish whether the password modification was authorized database administration or attacker-driven activity solely from the SQL statement.

However, when correlated with the established compromise of WEB-01, web-shell access, backup access, and subsequent account abuse, the activity becomes a high-priority indicator of potential credential manipulation.

A later event strengthens this correlation.

Relevant log evidence:

```text
12:00 - backup: SELECT customers, wp_users, UPDATE user_pass
```

The same sensitive operation appears again.

This repeated access to wp_users and modification of user_pass is inconsistent with a routine backup operation as represented by the supplied logs.

**Assessment:** High-confidence suspicious credential manipulation; compromise of the dbadmin account itself requires authentication evidence to conclusively establish.

---

## 8.8 Administrator Account — Brute-Force Target

A separate credential attack targeted the built-in Administrator account on DC-01.

Relevant log evidence:

```text
08:30:00–08:30:20
4625 Logon Type 3
User: Administrator
Source IP: 10.10.10.200
21 failed attempts
```

These are repeated failed network logons against the Administrator identity within approximately 20 seconds.

The evidence is consistent with automated password-guessing activity.

However, there is an important distinction between credential attack and credential compromise.

No successful authentication event for Administrator is present in the supplied evidence. Therefore, the logs establish repeated authentication failures, but they do not establish that the Administrator credentials were successfully compromised.

**Assessment:** Confirmed credential attack; successful compromise not demonstrated.

---

## 8.9 Relationship Between the Accounts

The available evidence indicates that the incident involved several identities with different roles:

| Account       | Evidence                                                           | Assessment                                                        |
| ------------- | ------------------------------------------------------------------ | ----------------------------------------------------------------- |
| www-data      | Successful external login; command execution; sudoers modification | Confirmed compromised                                             |
| maryam        | Repeated privileged sessions and malicious execution chain         | High-confidence compromised/abused                                |
| dbadmin       | Repeated modification of wp_users.user_pass                        | Suspicious credential manipulation; account compromise not proven |
| Administrator | 21 failed Type 3 logons                                            | Targeted by brute force; compromise not demonstrated              |
| deploy        | Successful SSH + Nginx administration                              | No compromise demonstrated                                        |
| webadmin      | Successful SSH + log review activity                               | No compromise demonstrated                                        |
| jenkins       | Successful SSH authentication                                      | No compromise demonstrated                                        |
| Veeam         | Backup-related authentication/activity                             | No compromise demonstrated                                        |

The key investigative point is that authentication success does not equal compromise, and suspicious activity does not automatically identify the human behind an account.

The strongest evidence of actual account abuse is the combination of identity, authentication, process execution, persistence, and network activity.

---

## 8.10 Credential Compromise Assessment

The available evidence supports the following incident-level assessment:

### Confirmed

* The attacker successfully authenticated to WEB-01 as www-data.
* The attacker used www-data to execute commands and establish persistent administrative capability.
* The maryam identity was subsequently associated with privileged sessions and a malicious execution chain.
* The Administrator account was subjected to repeated failed authentication attempts.
* Database activity repeatedly targeted WordPress credential records.

### Not conclusively established

* How the attacker originally obtained Mary's credentials.
* Whether Mary's password was stolen, guessed, reused, or obtained through session/token compromise.
* Whether dbadmin credentials themselves were compromised.
* Whether the Administrator password was successfully compromised.
* Whether the legitimate user Maryam personally performed any of the observed activity.

From an incident-response perspective, maryam should therefore be treated as a compromised identity, while www-data represents a confirmed attacker-controlled account. dbadmin requires additional authentication and database-audit evidence before declaring the account itself compromised.

The distinction is important because the remediation strategy differs: confirmed compromised identities should be contained and reset immediately, while unproven attribution should remain explicitly documented as an investigative hypothesis rather than being presented as fact.
