# 7. Web Shell and Persistence

## 7.1 Web Shell Deployment and Interactive Access

The available web-server evidence indicates that a web shell named `shell.php` was present on WEB-01 and subsequently accessed by the external attacker.

Relevant log evidence:

```text
09:06:00 - GET /shell.php
09:06:01 - POST /shell.php
```

The transition from a GET request to a POST request against the same PHP resource is consistent with an attacker interacting with a server-side web shell. A PHP file capable of receiving POST parameters can provide command execution through the web server process without requiring a conventional interactive shell.

This evidence is particularly significant because it follows the previously established compromise activity against WEB-01, including unauthorized access and payload execution.

The evidence therefore supports the assessment that `shell.php` was being used as a persistent web-access mechanism rather than representing normal WordPress functionality.

**Assessment:** Confirmed malicious activity.

---

## 7.2 Command Execution Through the Compromised Host

The preceding host activity provides additional evidence that the attacker had progressed beyond simple web access and obtained command execution on WEB-01.

Relevant log evidence:

```text
09:05:05 - whoami && hostname && ip a
09:05:10 - wget update.sh
09:05:15 - downloading secondary payload
09:05:20 - bash /tmp/update.sh
```

The command sequence demonstrates a recognizable post-compromise workflow:

1. Identify the current account and host.
2. Enumerate network configuration.
3. Retrieve an additional script.
4. Execute the downloaded script.

This sequence is inconsistent with ordinary WordPress administration and indicates execution of attacker-controlled commands on the server.

The `whoami`, `hostname`, and `ip a` commands are especially relevant because they establish that the actor was actively determining the execution context and network configuration after obtaining access.

**Assessment:** Confirmed post-compromise command execution.

---

## 7.3 Security Control Modification

The attacker subsequently modified security-related configuration on WEB-01.

Relevant log evidence:

```text
09:05:25 - systemctl stop nginx
09:05:30 - systemctl stop ufw
09:05:35 - chmod 777 /var/www/html -R
```

Stopping nginx and ufw materially changes the security posture of the host. In particular, disabling the host firewall can remove an important network-control layer, while recursively changing `/var/www/html` to mode `777` grants read, write, and execute permissions broadly.

These actions are not sufficient on their own to establish persistence, but in the context of the preceding payload execution and web-shell activity, they demonstrate deliberate weakening of host protections and modification of the web application environment.

**Assessment:** Confirmed malicious defense-impairment activity.

---

## 7.4 Privilege Persistence Through Sudoers Modification

The strongest persistence evidence in this stage is the modification of sudoers.

Relevant log evidence:

```text
09:05:40 - echo 'www-data ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
```

This command grants the `www-data` account unrestricted sudo access without requiring a password.

The significance is substantial: www-data is ordinarily associated with the web-server process and is not expected to possess unrestricted administrative privileges. By adding this entry to `/etc/sudoers`, the attacker establishes a mechanism through which the compromised web-server account can subsequently obtain elevated privileges.

This should not be described merely as "making www-data root." The log demonstrates the creation of a privilege-escalation and persistence path; it does not itself demonstrate that sudo was subsequently executed successfully.

The persistence mechanism nevertheless survives the termination of an individual web request or shell session, making it materially more serious than transient command execution.

**Assessment:** Confirmed persistence mechanism with a direct path to root-level privileges.

---

## 7.5 Persistence Correlation

The evidence forms a coherent sequence:

```text
Command execution
      |
      v
Payload retrieval
      |
      v
Payload execution
      |
      +------> Security controls disabled
      |
      +------> Web directory permissions weakened
      |
      +------> www-data granted passwordless sudo
      |
      v
Web shell accessed
      |
      v
Continued attacker-controlled access
```

The combination of `shell.php`, attacker-controlled payload execution, and modification of `/etc/sudoers` demonstrates that the compromise was not limited to an isolated web request.

The available evidence supports two distinct persistence/access mechanisms:

* **Web-layer persistence/access:** `shell.php`
* **Host-level privilege persistence:** `/etc/sudoers` modification

The evidence does not, however, establish from these logs alone whether the attacker successfully executed sudo and obtained a root shell. That distinction is important for maintaining evidentiary accuracy.

---

## 7.6 Assessment

The evidence associated with WEB-01 demonstrates a progression from command execution to establishment of durable attacker access.

The following are directly supported by the supplied logs:

* Attacker-controlled command execution occurred on WEB-01.
* An additional payload was downloaded and executed.
* Host security controls were deliberately disabled.
* Web-directory permissions were weakened.
* A PHP web shell was accessed.
* The `www-data` account was granted unrestricted passwordless sudo capability.

The most significant persistence artifact is the modification of `/etc/sudoers`, because it provides a durable mechanism for the compromised web-server identity to obtain administrative privileges.

**Conclusion:** WEB-01 should be considered fully compromised, with confirmed web-shell access and host-level persistence established.
