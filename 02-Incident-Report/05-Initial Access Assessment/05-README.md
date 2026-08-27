# 5. Initial Access Assessment

## 5.1 Assessment Objective

The objective of this section is to determine the most likely initial access vector responsible for the observed compromise, while clearly separating confirmed evidence from investigative hypotheses.

Based on the available evidence, the incident contains multiple possible access mechanisms, including:

* Compromise of the WordPress application through `wp-login.php`
* Compromise through previously obtained credentials
* SSH access using the `www-data` account
* Compromise of PC-MANAGER through a different, currently unidentified mechanism
* Phishing as a possible—but not yet proven—entry vector

The evidence does not currently support assigning a single definitive initial-access technique to the entire intrusion.

---

## 5.2 Earliest Confirmed Malicious Activity

The earliest clearly malicious activity in the available evidence occurs at 09:00 on WEB-01.

### Evidence

```text
09:00:00 - GET /wp-login.php
09:00:01–09:00:34 - POST /wp-login.php (34 attempts)
09:00:35 - GET /wp-admin/
09:00:36 - POST /admin-ajax.php
09:00:37 - GET /backup.tar.gz
```

The repeated authentication requests against `/wp-login.php`, followed immediately by access to `/wp-admin/`, represent a strong authentication-abuse pattern.

The transition is particularly significant:

```text
Repeated POST /wp-login.php
        ↓
GET /wp-admin/
        ↓
POST /admin-ajax.php
        ↓
GET /backup.tar.gz
```

This sequence is consistent with an attacker attempting to obtain valid WordPress credentials and subsequently accessing authenticated application functionality.

### Assessment

**High confidence:** malicious authentication activity against WEB-01.

The available logs strongly support the conclusion that the WordPress application was successfully accessed following the authentication attempts.

However, the logs provided do not explicitly contain a WordPress authentication-success event identifying the exact account that authenticated successfully.

Therefore, the report should avoid stating:

> "The attacker successfully brute-forced the WordPress administrator password."

as a confirmed fact.

The defensible statement is:

> The attacker performed repeated authentication attempts against WordPress and subsequently accessed `/wp-admin/`, strongly indicating successful authentication or possession of valid credentials.

---

## 5.3 External Origin of the Web Attack

The web attack originated from the external address:

```text
45.33.22.11
```

### Evidence

```text
09:00:00 - GET /wp-login.php
09:00:01–09:00:34 - POST /wp-login.php
09:00:35 - GET /wp-admin/
09:00:36 - POST /admin-ajax.php
09:00:37 - GET /backup.tar.gz
```

The subsequent server-side activity further associates this address with the compromise.

### Evidence

```text
09:05:00 - Accepted password for www-data from 45.33.22.11
09:05:01 - session opened
09:05:05 - whoami && hostname && ip a
09:05:10 - wget update.sh
09:05:15 - downloading secondary payload
09:05:20 - bash /tmp/update.sh
```

This establishes a significant relationship between the external source observed during the WordPress attack and subsequent direct access to WEB-01.

### Assessment

**High confidence:** 45.33.22.11 is associated with the compromise of WEB-01.

The evidence supports treating 45.33.22.11 as a primary intrusion-related IOC.

It should not, however, automatically be described as the definitive initial-access source for the entire enterprise intrusion until the relationship between WEB-01 and the later compromise of PC-MANAGER and DC-01 is established.

---

## 5.4 SSH as Initial Access vs. Post-Compromise Activity

The following event occurs shortly after the web compromise.

### Evidence

```text
09:05:00 - Accepted password for www-data from 45.33.22.11
09:05:01 - session opened
```

This demonstrates successful SSH authentication to WEB-01 using the `www-data` account.

However, the subsequent commands are more consistent with post-compromise reconnaissance and execution than with the original entry point.

### Evidence

```text
09:05:05 - whoami && hostname && ip a
09:05:10 - wget update.sh
09:05:15 - downloading secondary payload
09:05:20 - bash /tmp/update.sh
```

The sequence is:

```text
Authenticated session
        ↓
Host / identity discovery
        ↓
Payload retrieval
        ↓
Payload execution
```

### Assessment

SSH access is confirmed, but its role as the original initial-access vector is not confirmed.

The strongest interpretation is that the attacker already possessed or obtained access to WEB-01 and then used SSH for hands-on post-compromise activity.

The exact origin of the `www-data` credentials remains unresolved.

---

## 5.5 The 08:05 SSH Activity

Earlier SSH activity exists at 08:05.

### Evidence

```text
08:05:00 - Accepted password for deploy from 192.168.1.120 port 54321
08:05:01 - Accepted password for webadmin from 192.168.1.100 port 54322
08:05:02 - Accepted password for jenkins from 192.168.1.120 port 54323
```

The source addresses are internal:

```text
192.168.1.120
192.168.1.100
```

and the source ports are ephemeral client ports.

There is insufficient evidence in these events alone to classify the activity as malicious.

### Assessment

**Not established as initial access.**

The three successful sessions are anomalous enough to warrant contextual investigation, particularly because different accounts authenticate within three seconds, but there is no direct evidence in the supplied events connecting them to the later intrusion.

They should therefore remain contextual evidence rather than an identified intrusion vector.

---

## 5.6 08:07 Remote Interactive Logon

A separate event occurs on PC-MANAGER.

### Evidence

```text
08:07:00 - 4624 Logon Type 10
User: maryam
Source IP: 192.168.1.100

08:07:01 - 4672 Special Privileges
User: maryam
```

Logon Type 10 indicates a Remote Interactive logon, typically associated with technologies such as RDP.

However, the source address is:

```text
192.168.1.100
```

and the available evidence does not establish whether this represents:

* legitimate remote administration,
* Maryam's own remote session,
* an existing session being re-established,
* or malicious use of valid credentials.

Event 4672 also does not independently prove privilege escalation.

### Assessment

**Suspicious but insufficient to establish initial access.**

This event should not be used as evidence that the attacker initially compromised PC-MANAGER.

More importantly, the later malicious activity on the same system occurs at 09:40, leaving a substantial evidentiary gap.

---

## 5.7 Phishing as a Potential Initial Access Vector

The following email event is present.

### Evidence

```text
09:45:03–09:45:07
From: 194.34.132.15
Attachment: invoice_pdf.exe
```

An executable masquerading as a PDF-related invoice attachment is inherently suspicious and is consistent with a phishing delivery mechanism.

However, its timestamp is critical.

The malicious activity on PC-MANAGER begins before this email event.

### Evidence

```text
09:40:00 - cmd.exe /c whoami
09:40:01 - PowerShell -Enc
09:40:02 - Service Created: SysUpdate
09:40:03 - svchost.exe → 194.34.132.15:4444
```

Therefore, the supplied evidence cannot support the conclusion that this email caused the 09:40 compromise.

### Assessment

Phishing remains a viable hypothesis, but this specific email is not established as the initial-access vector.

Two possibilities remain:

1. The email represents a secondary phishing wave after the host was already compromised.
2. An earlier phishing message or another delivery mechanism, not present in the supplied logs, provided the original access.

At present, neither can be confirmed.

---

## 5.8 Determination of the Most Likely Initial Access

The available evidence produces the following confidence assessment:

| Candidate Vector                               | Evidence                                                   | Assessment                                                        |
| ---------------------------------------------- | ---------------------------------------------------------- | ----------------------------------------------------------------- |
| WordPress authentication attack against WEB-01 | 34 authentication attempts followed by `/wp-admin/` access | Most likely confirmed entry into WEB-01                           |
| SSH using www-data                             | Successful authentication from 45.33.22.11                 | Confirmed access, initial vector unconfirmed                      |
| 08:05 internal SSH sessions                    | Successful internal logins using multiple accounts         | Insufficient evidence                                             |
| 08:07 RDP/Remote Interactive session           | Event 4624 Type 10 for maryam                              | Suspicious, not proven malicious                                  |
| 09:45 phishing email                           | Executable attachment from 194.34.132.15                   | Potential secondary/alternative vector; not proven initial access |

---

## 5.9 Initial Access Conclusion

The earliest high-confidence malicious activity in the supplied evidence is the WordPress attack against WEB-01 at 09:00, originating from 45.33.22.11.

The sequence:

```text
09:00  WordPress authentication attack
   ↓
09:00  /wp-admin/ access
   ↓
09:00  backup.tar.gz access
   ↓
09:05  SSH authentication as www-data
   ↓
09:05  Host reconnaissance
   ↓
09:05  Payload download and execution
```

provides the strongest currently available evidence for the initial compromise of WEB-01.

However, the root cause of the initial credential acquisition remains undetermined. The supplied logs do not establish whether the attacker:

* brute-forced valid WordPress credentials,
* used previously compromised credentials,
* exploited a separate WordPress weakness,
* obtained credentials through an earlier event,
* or entered through another mechanism before 09:00.

Furthermore, the evidence does not yet prove how the attacker progressed from WEB-01 to PC-MANAGER and subsequently to DC-01.

Accordingly, the incident should currently be documented as:

> **Initial Access to WEB-01 is assessed with high confidence to have occurred through successful abuse of the WordPress authentication interface, following repeated authentication attempts from 45.33.22.11. The underlying credential acquisition mechanism and the initial access vector for PC-MANAGER remain undetermined.**

This distinction is important: we can establish the first confirmed compromised asset without falsely claiming that we have established the complete enterprise-wide initial-access mechanism.
