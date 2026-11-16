# Rule reference

aegis ships 81 rules covering the controls that most often decide whether a Linux host survives an audit. Every rule is plain YAML in `src/aegis/rules/`; this page is generated from that pack, so edit the YAML and run `make docs` instead of editing this file.

| Property | Value |
| --- | --- |
| Rules | 81 |
| Categories | 9 |
| Rules with an automated safe fix | 35 |
| Manual controls | 46 |
| Severity mix | 5 critical, 38 high, 35 medium, 3 low |

## Scoring model

Each evaluated rule contributes its severity weight to the denominator. A passing rule contributes the same weight to the numerator, so the score is `100 * passed_weight / evaluated_weight` and not a raw pass rate. Not applicable rules and suppressed baseline entries are removed from both sides, which keeps image audits comparable across hosts that legitimately differ.

| Severity | Weight | Grade impact |
| --- | --- | --- |
| critical | 10 | A single failure costs 10 points of the weighted total |
| high | 5 | Two failures cost roughly one critical |
| medium | 2 | Hardening depth and defence in depth |
| low | 1 | Hygiene and logging quality |
| info | 0 | Context only, never affects the gate |

| Grade | Minimum score |
| --- | --- |
| A | 90 |
| B | 80 |
| C | 70 |
| D | 60 |
| F | 0 |

## Coverage summary

| Category | Rules | Critical | High | Medium | Low | Automated fixes |
| --- | --- | --- | --- | --- | --- | --- |
| SSH | 13 | 2 | 3 | 6 | 2 | 11 |
| Kernel | 14 | 0 | 2 | 11 | 1 | 10 |
| Filesystem | 10 | 1 | 9 | 0 | 0 | 5 |
| Accounts | 18 | 2 | 7 | 9 | 0 | 7 |
| Logging | 7 | 0 | 3 | 4 | 0 | 1 |
| Firewall | 3 | 0 | 3 | 0 | 0 | 0 |
| Packages | 5 | 0 | 3 | 2 | 0 | 0 |
| Services | 6 | 0 | 3 | 3 | 0 | 0 |
| Crypto | 5 | 0 | 5 | 0 | 0 | 1 |

## Rule catalogue

### SSH

| ID | Severity | Title | CIS reference | Check | Fix |
| --- | --- | --- | --- | --- | --- |
| [AEGIS-0002](#aegis-0002) | critical | SSH root login is permitted | CIS Ubuntu Linux 22.04 5.3.7 | `sshd` | `sshd_set` |
| [AEGIS-0004](#aegis-0004) | critical | SSH accepts empty passwords | CIS Ubuntu Linux 22.04 5.3.11 | `sshd` | `sshd_set` |
| [AEGIS-0001](#aegis-0001) | high | SSH server configuration is not group or world accessible | CIS Ubuntu Linux 22.04 5.3.1 | `file_mode` | `file_mode` |
| [AEGIS-0003](#aegis-0003) | high | SSH password authentication is enabled | CIS Ubuntu Linux 22.04 5.3.4 | `sshd` | `sshd_set` |
| [AEGIS-0007](#aegis-0007) | high | SSH host-based authentication is enabled | CIS Ubuntu Linux 22.04 5.3.10 | `sshd` | `sshd_set` |
| [AEGIS-0005](#aegis-0005) | medium | SSH MaxAuthTries exceeds four | CIS Ubuntu Linux 22.04 5.3.8 | `sshd` | `sshd_set` |
| [AEGIS-0006](#aegis-0006) | medium | SSH IgnoreRhosts is not enabled | CIS Ubuntu Linux 22.04 5.3.9 | `sshd` | `sshd_set` |
| [AEGIS-0008](#aegis-0008) | medium | SSH user environment processing is enabled | CIS Ubuntu Linux 22.04 5.3.12 | `sshd` | `sshd_set` |
| [AEGIS-0009](#aegis-0009) | medium | SSH PAM integration is disabled | CIS Ubuntu Linux 22.04 5.3.6 | `sshd` | `sshd_set` |
| [AEGIS-0011](#aegis-0011) | medium | SSH LoginGraceTime exceeds sixty seconds | CIS Ubuntu Linux 22.04 5.3.17 | `sshd` | `sshd_set` |
| [AEGIS-0012](#aegis-0012) | medium | SSH access is not restricted to named users or groups | CIS Ubuntu Linux 22.04 5.3.4 | `file_content` | manual |
| [AEGIS-0010](#aegis-0010) | low | SSH LogLevel is not INFO or VERBOSE | CIS Ubuntu Linux 22.04 5.3.5 | `sshd` | `sshd_set` |
| [AEGIS-0081](#aegis-0081) | low | The SSH warning banner file is missing | CIS Ubuntu Linux 22.04 5.3.18 | `file_exists` | manual |

### Kernel

| ID | Severity | Title | CIS reference | Check | Fix |
| --- | --- | --- | --- | --- | --- |
| [AEGIS-0018](#aegis-0018) | high | Address space layout randomization is not fully enabled | CIS Ubuntu Linux 22.04 1.5.1 | `sysctl` | `sysctl_set` |
| [AEGIS-0022](#aegis-0022) | high | Source-routed IPv4 packets are accepted | CIS Ubuntu Linux 22.04 3.2.1 | `sysctl` | `sysctl_set` |
| [AEGIS-0019](#aegis-0019) | medium | Setuid core dumps are not restricted | CIS Ubuntu Linux 22.04 1.5.4 | `sysctl` | `sysctl_set` |
| [AEGIS-0020](#aegis-0020) | medium | IPv4 forwarding is enabled | CIS Ubuntu Linux 22.04 3.1.1 | `sysctl` | `sysctl_set` |
| [AEGIS-0021](#aegis-0021) | medium | IPv4 packet redirect sending is enabled | CIS Ubuntu Linux 22.04 3.1.2 | `sysctl` | `sysctl_set` |
| [AEGIS-0023](#aegis-0023) | medium | ICMP redirects are accepted | CIS Ubuntu Linux 22.04 3.2.2 | `sysctl` | `sysctl_set` |
| [AEGIS-0025](#aegis-0025) | medium | Reverse path filtering is disabled | CIS Ubuntu Linux 22.04 3.2.7 | `sysctl` | `sysctl_set` |
| [AEGIS-0026](#aegis-0026) | medium | TCP SYN cookies are disabled | CIS Ubuntu Linux 22.04 3.2.8 | `sysctl` | `sysctl_set` |
| [AEGIS-0027](#aegis-0027) | medium | IPv6 router advertisements are accepted | CIS Ubuntu Linux 22.04 3.2.9 | `sysctl` | `sysctl_set` |
| [AEGIS-0028](#aegis-0028) | medium | The cramfs kernel module is available | CIS Ubuntu Linux 22.04 1.1.1.1 | `kernel_module` | manual |
| [AEGIS-0029](#aegis-0029) | medium | The freevxfs kernel module is available | CIS Ubuntu Linux 22.04 1.1.1.2 | `kernel_module` | manual |
| [AEGIS-0030](#aegis-0030) | medium | The udf kernel module is available | CIS Ubuntu Linux 22.04 1.1.1.6 | `kernel_module` | manual |
| [AEGIS-0031](#aegis-0031) | medium | The SCTP kernel module is available | CIS Ubuntu Linux 22.04 3.3.2 | `kernel_module` | manual |
| [AEGIS-0024](#aegis-0024) | low | Suspicious packets are not logged | CIS Ubuntu Linux 22.04 3.2.4 | `sysctl` | `sysctl_set` |

### Filesystem

| ID | Severity | Title | CIS reference | Check | Fix |
| --- | --- | --- | --- | --- | --- |
| [AEGIS-0034](#aegis-0034) | critical | /etc/shadow is accessible to non-root users | CIS Ubuntu Linux 22.04 6.1.5 | `file_mode` | `file_mode` |
| [AEGIS-0032](#aegis-0032) | high | /etc/passwd permissions are too broad | CIS Ubuntu Linux 22.04 6.1.1 | `file_mode` | `file_mode` |
| [AEGIS-0033](#aegis-0033) | high | /etc/group permissions are too broad | CIS Ubuntu Linux 22.04 6.1.3 | `file_mode` | `file_mode` |
| [AEGIS-0035](#aegis-0035) | high | /etc/shadow- backup is accessible to non-root users | CIS Ubuntu Linux 22.04 6.1.6 | `file_mode` | `file_mode` |
| [AEGIS-0036](#aegis-0036) | high | /etc/gshadow is accessible to non-root users | CIS Ubuntu Linux 22.04 6.1.7 | `file_mode` | `file_mode` |
| [AEGIS-0037](#aegis-0037) | high | World-writable files exist | CIS Ubuntu Linux 22.04 6.1.9 | `world_writable` | manual |
| [AEGIS-0038](#aegis-0038) | high | Cron configuration permissions are too permissive | CIS Ubuntu Linux 22.04 5.1.2 | `cron_permissions` | manual |
| [AEGIS-0039](#aegis-0039) | high | Cron and at are not restricted by allow lists | CIS Ubuntu Linux 22.04 5.1.8 | `cron_permissions` | manual |
| [AEGIS-0040](#aegis-0040) | high | /tmp is missing nodev, nosuid, or noexec mount options | CIS Ubuntu Linux 22.04 1.1.2.2-1.1.2.4 | `mount_option` | manual |
| [AEGIS-0041](#aegis-0041) | high | /dev/shm is missing nodev, nosuid, or noexec mount options | CIS Ubuntu Linux 22.04 1.1.3 | `mount_option` | manual |

### Accounts

| ID | Severity | Title | CIS reference | Check | Fix |
| --- | --- | --- | --- | --- | --- |
| [AEGIS-0042](#aegis-0042) | critical | More than one account has UID 0 | CIS Ubuntu Linux 22.04 6.2.3 | `account` | manual |
| [AEGIS-0043](#aegis-0043) | critical | Accounts with empty password fields exist | CIS Ubuntu Linux 22.04 6.2.2 | `account` | manual |
| [AEGIS-0044](#aegis-0044) | high | Accounts are not using shadowed passwords | CIS Ubuntu Linux 22.04 6.2.1 | `account` | manual |
| [AEGIS-0045](#aegis-0045) | high | System accounts have unlocked passwords | CIS Ubuntu Linux 22.04 5.5.2 | `account` | manual |
| [AEGIS-0047](#aegis-0047) | high | Duplicate UIDs exist | CIS Ubuntu Linux 22.04 6.2.14 | `account` | manual |
| [AEGIS-0050](#aegis-0050) | high | Password aging exceeds policy | CIS Ubuntu Linux 22.04 5.5.1.2 | `account` | manual |
| [AEGIS-0052](#aegis-0052) | high | login.defs PASS_MAX_DAYS exceeds 365 | CIS Ubuntu Linux 22.04 5.5.1.2 | `login_defs` | `login_defs_set` |
| [AEGIS-0056](#aegis-0056) | high | Password minimum length is below fourteen characters | CIS Ubuntu Linux 22.04 5.4.1 | `password_quality` | `pwquality_set` |
| [AEGIS-0059](#aegis-0059) | high | PAM does not invoke pam_pwquality | CIS Ubuntu Linux 22.04 5.4.1 | `file_content` | manual |
| [AEGIS-0046](#aegis-0046) | medium | The root account does not have a valid login shell | CIS Ubuntu Linux 22.04 5.5.2 (root account) | `account` | manual |
| [AEGIS-0048](#aegis-0048) | medium | Login users have missing home directories | CIS Ubuntu Linux 22.04 6.2.5 | `account` | manual |
| [AEGIS-0049](#aegis-0049) | medium | User home directories are more permissive than 0750 | CIS Ubuntu Linux 22.04 6.2.6 | `account` | manual |
| [AEGIS-0051](#aegis-0051) | medium | Inactive accounts are not locked after thirty days | CIS Ubuntu Linux 22.04 5.5.1.4 | `account` | manual |
| [AEGIS-0053](#aegis-0053) | medium | login.defs PASS_MIN_DAYS is below one | CIS Ubuntu Linux 22.04 5.5.1.1 | `login_defs` | `login_defs_set` |
| [AEGIS-0054](#aegis-0054) | medium | login.defs PASS_WARN_AGE is below seven days | CIS Ubuntu Linux 22.04 5.5.1.3 | `login_defs` | `login_defs_set` |
| [AEGIS-0055](#aegis-0055) | medium | Default user umask is less restrictive than 027 | CIS Ubuntu Linux 22.04 5.5.4 | `login_defs` | `login_defs_set` |
| [AEGIS-0057](#aegis-0057) | medium | Password complexity requires fewer than four character classes | CIS Ubuntu Linux 22.04 5.4.1 | `password_quality` | `pwquality_set` |
| [AEGIS-0058](#aegis-0058) | medium | Password quality enforcement is not enabled | CIS Ubuntu Linux 22.04 5.4.1 | `password_quality` | `pwquality_set` |

### Logging

| ID | Severity | Title | CIS reference | Check | Fix |
| --- | --- | --- | --- | --- | --- |
| [AEGIS-0060](#aegis-0060) | high | auditd is not installed | CIS Ubuntu Linux 22.04 4.1.1.1 | `auditd` | manual |
| [AEGIS-0061](#aegis-0061) | high | auditd is not enabled at boot | CIS Ubuntu Linux 22.04 4.1.1.2 | `auditd` | manual |
| [AEGIS-0062](#aegis-0062) | high | auditd deletes logs when the disk fills | CIS Ubuntu Linux 22.04 4.1.2.2 | `auditd` | manual |
| [AEGIS-0063](#aegis-0063) | medium | auditd does not warn by email when logs run low | CIS Ubuntu Linux 22.04 4.1.2.4 | `auditd` | manual |
| [AEGIS-0064](#aegis-0064) | medium | Kernel auditing is not enabled at boot | CIS Ubuntu Linux 22.04 4.1.3 | `auditd` | manual |
| [AEGIS-0065](#aegis-0065) | medium | Journald storage is not persistent | CIS Ubuntu Linux 22.04 4.2.1.4 | `file_content` | manual |
| [AEGIS-0066](#aegis-0066) | medium | System log file permissions are too broad | CIS Ubuntu Linux 22.04 4.2.3 | `file_mode` | `file_mode` |

### Firewall

| ID | Severity | Title | CIS reference | Check | Fix |
| --- | --- | --- | --- | --- | --- |
| [AEGIS-0067](#aegis-0067) | high | The UFW host firewall is not enabled | CIS Ubuntu Linux 22.04 3.5.1.2 | `firewall` | manual |
| [AEGIS-0068](#aegis-0068) | high | UFW default inbound policy is not deny | CIS Ubuntu Linux 22.04 3.5.1.3 | `firewall` | manual |
| [AEGIS-0069](#aegis-0069) | high | No supported host firewall is enabled | CIS Ubuntu Linux 22.04 3.5 (host-based firewall) | `firewall` | manual |

### Packages

| ID | Severity | Title | CIS reference | Check | Fix |
| --- | --- | --- | --- | --- | --- |
| [AEGIS-0070](#aegis-0070) | high | A telnet server is installed | CIS Distribution Independent Linux 2.2 (legacy network services) | `package` | manual |
| [AEGIS-0071](#aegis-0071) | high | An rsh server is installed | CIS Distribution Independent Linux 2.3 (rsh services) | `package` | manual |
| [AEGIS-0072](#aegis-0072) | high | A TFTP server is installed | CIS Distribution Independent Linux 2.2 (tftp services) | `package` | manual |
| [AEGIS-0073](#aegis-0073) | medium | xinetd is installed | CIS Ubuntu Linux 22.04 2.2.1 | `package` | manual |
| [AEGIS-0074](#aegis-0074) | medium | Automatic security updates are not installed | CIS Ubuntu Linux 22.04 1.9 | `package` | manual |

### Services

| ID | Severity | Title | CIS reference | Check | Fix |
| --- | --- | --- | --- | --- | --- |
| [AEGIS-0077](#aegis-0077) | high | The telnet socket is enabled | CIS Distribution Independent Linux 2.2 (telnet services) | `service` | manual |
| [AEGIS-0078](#aegis-0078) | high | The rsh socket is enabled | CIS Distribution Independent Linux 2.3 (rsh services) | `service` | manual |
| [AEGIS-0080](#aegis-0080) | high | Legacy clear-text or unauthenticated ports are listening | CIS Distribution Independent Linux 2.2-2.3 (legacy services) | `listening_port` | manual |
| [AEGIS-0075](#aegis-0075) | medium | The cron daemon is not enabled | CIS Ubuntu Linux 22.04 5.1.1 | `service` | manual |
| [AEGIS-0076](#aegis-0076) | medium | The SSH service is not enabled | CIS Ubuntu Linux 22.04 5.3 (SSH service) | `service` | manual |
| [AEGIS-0079](#aegis-0079) | medium | The tftp socket is enabled | CIS Distribution Independent Linux 2.2 (tftp services) | `service` | manual |

### Crypto

| ID | Severity | Title | CIS reference | Check | Fix |
| --- | --- | --- | --- | --- | --- |
| [AEGIS-0013](#aegis-0013) | high | SSH allows weak CBC or legacy ciphers | CIS Ubuntu Linux 22.04 5.3.13 | `file_content` | manual |
| [AEGIS-0014](#aegis-0014) | high | SSH allows weak MAC algorithms | CIS Ubuntu Linux 22.04 5.3.14 | `file_content` | manual |
| [AEGIS-0015](#aegis-0015) | high | SSH allows SHA-1 key exchange algorithms | CIS Ubuntu Linux 22.04 5.3.15 | `file_content` | manual |
| [AEGIS-0016](#aegis-0016) | high | OpenSSL minimum protocol version is below TLS 1.2 | CIS Distribution Independent Linux 1.6 (system-wide crypto policy) | `file_content` | manual |
| [AEGIS-0017](#aegis-0017) | high | Password hashing does not use SHA-512 or yescrypt | CIS Ubuntu Linux 22.04 5.4.4 | `login_defs` | `login_defs_set` |

## Remediation types

`--remediate` prints the plan and writes nothing. `--apply` executes only the structured fixes below, never a shell command, and writes a `.aegis.bak` backup next to each modified file before an atomic replace. Anything labelled manual requires human judgement, a service restart, or a package operation, so aegis prints the command and leaves it to you.

| Fix type | Behaviour |
| --- | --- |
| `file_mode` | Set the mode of an existing file (chmod equivalent, never executed as a shell). |
| `file_content` | Append a line or replace a matching line in a text file. |
| `sshd_set` | Set or replace a single keyword in sshd_config, preserving the rest of the file. |
| `sysctl_set` | Set or replace a key in a sysctl file, preserving comments and formatting. |

## Rule details

### AEGIS-0001

**SSH server configuration is not group or world accessible**

`AEGIS-0001` | severity `high` | category SSH | CIS Ubuntu Linux 22.04 5.3.1

/etc/ssh/sshd_config controls authentication and transport policy. It must be owned by root and readable only by root, otherwise local users can learn or alter the server's security posture.

| Field | Value |
| --- | --- |
| Check | `file_mode` |
| Parameters | `{max_mode: '0600', missing: fail, path: /etc/ssh/sshd_config}` |
| Tags | `ssh`, `permissions` |
| Automated fix | yes |
| Fix type | `file_mode` |

Remediation: Restrict /etc/ssh/sshd_config to mode 0600 and ownership root:root.

```sh
chmod 600 /etc/ssh/sshd_config && chown root:root /etc/ssh/sshd_config
```

### AEGIS-0002

**SSH root login is permitted**

`AEGIS-0002` | severity `critical` | category SSH | CIS Ubuntu Linux 22.04 5.3.7

Direct root logins remove accountability and expose the most privileged account to password guessing. Administrators should log in as themselves and escalate with sudo.

| Field | Value |
| --- | --- |
| Check | `sshd` |
| Parameters | `{default: prohibit-password, key: PermitRootLogin, value: 'no'}` |
| Tags | `ssh`, `authentication` |
| Automated fix | yes |
| Fix type | `sshd_set` |

Remediation: Set PermitRootLogin no in the global section of /etc/ssh/sshd_config and reload sshd.

```sh
systemctl reload ssh
```

### AEGIS-0003

**SSH password authentication is enabled**

`AEGIS-0003` | severity `high` | category SSH | CIS Ubuntu Linux 22.04 5.3.4

Password authentication permits online guessing and credential stuffing. Key-based authentication should be required for interactive access.

| Field | Value |
| --- | --- |
| Check | `sshd` |
| Parameters | `{default: 'yes', key: PasswordAuthentication, value: 'no'}` |
| Tags | `ssh`, `authentication` |
| Automated fix | yes |
| Fix type | `sshd_set` |

Remediation: Set PasswordAuthentication no after confirming every administrator has a working key.

```sh
sshd -t && systemctl reload ssh
```

### AEGIS-0004

**SSH accepts empty passwords**

`AEGIS-0004` | severity `critical` | category SSH | CIS Ubuntu Linux 22.04 5.3.11

PermitEmptyPasswords yes allows accounts with blank passwords to authenticate over the network and should never be enabled.

| Field | Value |
| --- | --- |
| Check | `sshd` |
| Parameters | `{default: 'no', key: PermitEmptyPasswords, value: 'no'}` |
| Tags | `ssh`, `authentication` |
| Automated fix | yes |
| Fix type | `sshd_set` |

Remediation: Set PermitEmptyPasswords no and ensure no account has an empty password hash.

```sh
systemctl reload ssh
```

### AEGIS-0005

**SSH MaxAuthTries exceeds four**

`AEGIS-0005` | severity `medium` | category SSH | CIS Ubuntu Linux 22.04 5.3.8

Limiting authentication attempts per connection reduces the effectiveness of online password guessing and slows brute-force attempts.

| Field | Value |
| --- | --- |
| Check | `sshd` |
| Parameters | `{default: '6', key: MaxAuthTries, value: ['1', '2', '3', '4']}` |
| Tags | `ssh`, `brute-force` |
| Automated fix | yes |
| Fix type | `sshd_set` |

Remediation: Set MaxAuthTries 4 or lower.

### AEGIS-0006

**SSH IgnoreRhosts is not enabled**

`AEGIS-0006` | severity `medium` | category SSH | CIS Ubuntu Linux 22.04 5.3.9

Host-based rhosts authentication bypasses normal account authentication and trusts client-supplied identity.

| Field | Value |
| --- | --- |
| Check | `sshd` |
| Parameters | `{default: 'yes', key: IgnoreRhosts, value: 'yes'}` |
| Tags | `ssh`, `authentication` |
| Automated fix | yes |
| Fix type | `sshd_set` |

Remediation: Set IgnoreRhosts yes.

### AEGIS-0007

**SSH host-based authentication is enabled**

`AEGIS-0007` | severity `high` | category SSH | CIS Ubuntu Linux 22.04 5.3.10

HostbasedAuthentication trusts the client host identity rather than the user's cryptographic credentials and should remain disabled.

| Field | Value |
| --- | --- |
| Check | `sshd` |
| Parameters | `{default: 'no', key: HostbasedAuthentication, value: 'no'}` |
| Tags | `ssh`, `authentication` |
| Automated fix | yes |
| Fix type | `sshd_set` |

Remediation: Set HostbasedAuthentication no.

### AEGIS-0008

**SSH user environment processing is enabled**

`AEGIS-0008` | severity `medium` | category SSH | CIS Ubuntu Linux 22.04 5.3.12

PermitUserEnvironment allows users to set environment variables that may influence login processing and should be disabled unless explicitly required.

| Field | Value |
| --- | --- |
| Check | `sshd` |
| Parameters | `{default: 'no', key: PermitUserEnvironment, value: 'no'}` |
| Tags | `ssh`, `environment` |
| Automated fix | yes |
| Fix type | `sshd_set` |

Remediation: Set PermitUserEnvironment no.

### AEGIS-0009

**SSH PAM integration is disabled**

`AEGIS-0009` | severity `medium` | category SSH | CIS Ubuntu Linux 22.04 5.3.6

UsePAM yes is required for account lockout, password quality, session limits, and other PAM-enforced controls to apply to SSH sessions.

| Field | Value |
| --- | --- |
| Check | `sshd` |
| Parameters | `{default: 'no', key: UsePAM, value: 'yes'}` |
| Tags | `ssh`, `pam` |
| Automated fix | yes |
| Fix type | `sshd_set` |

Remediation: Set UsePAM yes and verify PAM services still permit intended authentication.

### AEGIS-0010

**SSH LogLevel is not INFO or VERBOSE**

`AEGIS-0010` | severity `low` | category SSH | CIS Ubuntu Linux 22.04 5.3.5

INFO or VERBOSE logging records authentication events and key fingerprints needed for investigation without logging sensitive session data.

| Field | Value |
| --- | --- |
| Check | `sshd` |
| Parameters | `{default: INFO, key: LogLevel, value: [INFO, VERBOSE]}` |
| Tags | `ssh`, `logging` |
| Automated fix | yes |
| Fix type | `sshd_set` |

Remediation: Set LogLevel INFO or VERBOSE.

### AEGIS-0011

**SSH LoginGraceTime exceeds sixty seconds**

`AEGIS-0011` | severity `medium` | category SSH | CIS Ubuntu Linux 22.04 5.3.17

A long unauthenticated window consumes connection slots and extends exposure to pre-authentication attacks.

| Field | Value |
| --- | --- |
| Check | `sshd` |
| Parameters | `{default: '120', key: LoginGraceTime, value: ['30', '60']}` |
| Tags | `ssh`, `timeout` |
| Automated fix | yes |
| Fix type | `sshd_set` |

Remediation: Set LoginGraceTime to 60 seconds or less.

### AEGIS-0012

**SSH access is not restricted to named users or groups**

`AEGIS-0012` | severity `medium` | category SSH | CIS Ubuntu Linux 22.04 5.3.4

An AllowUsers or AllowGroups directive limits which accounts may authenticate over SSH, reducing the blast radius of compromised service accounts.

| Field | Value |
| --- | --- |
| Check | `file_content` |
| Parameters | `{missing: fail, path: /etc/ssh/sshd_config, pattern: '(?m)^\s*(AllowUsers\|AllowGroups)\s+\S+',   state: present}` |
| Tags | `ssh`, `access-control` |
| Automated fix | no |

Remediation: Add AllowGroups ssh-users (or an equivalent AllowUsers list) to sshd_config.

```sh
printf '\nAllowGroups ssh-users\n' >> /etc/ssh/sshd_config && sshd -t
```

### AEGIS-0013

**SSH allows weak CBC or legacy ciphers**

`AEGIS-0013` | severity `high` | category Crypto | CIS Ubuntu Linux 22.04 5.3.13

Ancient ciphers such as 3DES, RC4, Blowfish, CAST, and CBC-mode AES lack modern integrity guarantees or have small effective key sizes. Explicitly configuring strong AEAD ciphers removes them from negotiation.

| Field | Value |
| --- | --- |
| Check | `file_content` |
| Parameters | `{missing: fail, path: /etc/ssh/sshd_config, pattern: '(?im)^\s*Ciphers\s+.*\b(3des-cbc\|arcfour\|arcfour128\|arcfour256\|blowfish-cbc\|cast128-cbc\|des-cbc\|aes128-cbc\|aes192-cbc\|aes256-cbc)\b',   state: absent}` |
| Tags | `crypto`, `ssh`, `ciphers` |
| Automated fix | no |

Remediation: Configure only AEAD ciphers, for example chacha20-poly1305@openssh.com and aes256-gcm@openssh.com.

```sh
sshd -T | grep -i '^ciphers'
```

### AEGIS-0014

**SSH allows weak MAC algorithms**

`AEGIS-0014` | severity `high` | category Crypto | CIS Ubuntu Linux 22.04 5.3.14

MD5 and truncated SHA-1 MACs provide insufficient integrity protection. ETM SHA-2 or AEAD ciphers should be used instead.

| Field | Value |
| --- | --- |
| Check | `file_content` |
| Parameters | `{missing: fail, path: /etc/ssh/sshd_config, pattern: '(?im)^\s*MACs\s+.*\b(hmac-md5\|hmac-md5-96\|hmac-sha1-96\|umac-64@openssh\.com)\b',   state: absent}` |
| Tags | `crypto`, `ssh`, `mac` |
| Automated fix | no |

Remediation: Configure ETM SHA-2 MACs such as hmac-sha2-512-etm@openssh.com and hmac-sha2-256-etm@openssh.com.

```sh
sshd -T | grep -i '^macs'
```

### AEGIS-0015

**SSH allows SHA-1 key exchange algorithms**

`AEGIS-0015` | severity `high` | category Crypto | CIS Ubuntu Linux 22.04 5.3.15

SHA-1 based Diffie-Hellman key exchange is deprecated and has known weaknesses. Curve25519 or SHA-2 group exchange should be used.

| Field | Value |
| --- | --- |
| Check | `file_content` |
| Parameters | `{missing: fail, path: /etc/ssh/sshd_config, pattern: '(?im)^\s*KexAlgorithms\s+.*(diffie-hellman-group1-sha1\|diffie-hellman-group14-sha1\|diffie-hellman-group-exchange-sha1)',   state: absent}` |
| Tags | `crypto`, `ssh`, `key-exchange` |
| Automated fix | no |

Remediation: Configure curve25519-sha256 and SHA-2 group exchange algorithms only.

```sh
sshd -T | grep -i '^kexalgorithms'
```

### AEGIS-0016

**OpenSSL minimum protocol version is below TLS 1.2**

`AEGIS-0016` | severity `high` | category Crypto | CIS Distribution Independent Linux 1.6 (system-wide crypto policy)

The system OpenSSL configuration must not permit TLS 1.0 or 1.1, which are deprecated and lack modern cipher suites.

| Field | Value |
| --- | --- |
| Check | `file_content` |
| Parameters | `{missing: fail, path: /etc/ssl/openssl.cnf, pattern: '(?m)^\s*MinProtocol\s*=\s*TLSv1\.[23]\s*$',   state: present}` |
| Tags | `crypto`, `tls`, `openssl` |
| Automated fix | no |

Remediation: Set MinProtocol = TLSv1.2 in the system stanza of /etc/ssl/openssl.cnf.

```sh
grep -R '^[[:space:]]*MinProtocol' /etc/ssl/openssl.cnf
```

### AEGIS-0017

**Password hashing does not use SHA-512 or yescrypt**

`AEGIS-0017` | severity `high` | category Crypto | CIS Ubuntu Linux 22.04 5.4.4

ENCRYPT_METHOD in login.defs determines the hash for new passwords. SHA-512 or yescrypt is required; DES and MD5-based hashes are not acceptable.

| Field | Value |
| --- | --- |
| Check | `login_defs` |
| Parameters | `{allowed: [SHA512, YESCRYPT], key: ENCRYPT_METHOD, missing: fail}` |
| Tags | `crypto`, `passwords`, `hashing` |
| Automated fix | yes |
| Fix type | `login_defs_set` |

Remediation: Set ENCRYPT_METHOD SHA512 or YESCRYPT and rotate weak existing hashes.

### AEGIS-0018

**Address space layout randomization is not fully enabled**

`AEGIS-0018` | severity `high` | category Kernel | CIS Ubuntu Linux 22.04 1.5.1

kernel.randomize_va_space must be 2 so that stack, heap, and shared library mappings are randomized, raising the cost of memory corruption exploits.

| Field | Value |
| --- | --- |
| Check | `sysctl` |
| Parameters | `{key: kernel.randomize_va_space, value: '2'}` |
| Tags | `kernel`, `memory`, `aslr` |
| Automated fix | yes |
| Fix type | `sysctl_set` |

Remediation: Set kernel.randomize_va_space = 2 in /etc/sysctl.conf and apply it with sysctl -p.

```sh
sysctl -w kernel.randomize_va_space=2
```

### AEGIS-0019

**Setuid core dumps are not restricted**

`AEGIS-0019` | severity `medium` | category Kernel | CIS Ubuntu Linux 22.04 1.5.4

fs.suid_dumpable must be 0 so that crashing setuid programs cannot write memory images that may contain credentials or secrets.

| Field | Value |
| --- | --- |
| Check | `sysctl` |
| Parameters | `{key: fs.suid_dumpable, value: '0'}` |
| Tags | `kernel`, `core-dumps` |
| Automated fix | yes |
| Fix type | `sysctl_set` |

Remediation: Set fs.suid_dumpable = 0 in /etc/sysctl.conf.

### AEGIS-0020

**IPv4 forwarding is enabled**

`AEGIS-0020` | severity `medium` | category Kernel | CIS Ubuntu Linux 22.04 3.1.1

A host that is not a router must not forward packets. Forwarding enables traffic to cross network boundaries the host was not designed to bridge.

| Field | Value |
| --- | --- |
| Check | `sysctl` |
| Parameters | `{key: net.ipv4.ip_forward, value: '0'}` |
| Tags | `kernel`, `network` |
| Automated fix | yes |
| Fix type | `sysctl_set` |

Remediation: Set net.ipv4.ip_forward = 0 unless the host is an intentional router or container host requiring it.

### AEGIS-0021

**IPv4 packet redirect sending is enabled**

`AEGIS-0021` | severity `medium` | category Kernel | CIS Ubuntu Linux 22.04 3.1.2

An end host should not send ICMP redirects. Redirects can rewrite another host's routing decisions and are a classic traffic interception primitive.

| Field | Value |
| --- | --- |
| Check | `sysctl` |
| Parameters | `{key: net.ipv4.conf.all.send_redirects, value: '0'}` |
| Tags | `kernel`, `network`, `icmp` |
| Automated fix | yes |
| Fix type | `sysctl_set` |

Remediation: Set net.ipv4.conf.all.send_redirects = 0.

### AEGIS-0022

**Source-routed IPv4 packets are accepted**

`AEGIS-0022` | severity `high` | category Kernel | CIS Ubuntu Linux 22.04 3.2.1

Source routing lets a sender dictate the path a packet takes and is not required on normal end hosts.

| Field | Value |
| --- | --- |
| Check | `sysctl` |
| Parameters | `{key: net.ipv4.conf.all.accept_source_route, value: '0'}` |
| Tags | `kernel`, `network`, `routing` |
| Automated fix | yes |
| Fix type | `sysctl_set` |

Remediation: Set net.ipv4.conf.all.accept_source_route = 0 on all interfaces.

### AEGIS-0023

**ICMP redirects are accepted**

`AEGIS-0023` | severity `medium` | category Kernel | CIS Ubuntu Linux 22.04 3.2.2

Accepting ICMP redirects allows an attacker on the local segment to alter the host's routing table and intercept traffic.

| Field | Value |
| --- | --- |
| Check | `sysctl` |
| Parameters | `{key: net.ipv4.conf.all.accept_redirects, value: '0'}` |
| Tags | `kernel`, `network`, `icmp` |
| Automated fix | yes |
| Fix type | `sysctl_set` |

Remediation: Set net.ipv4.conf.all.accept_redirects = 0.

### AEGIS-0024

**Suspicious packets are not logged**

`AEGIS-0024` | severity `low` | category Kernel | CIS Ubuntu Linux 22.04 3.2.4

net.ipv4.conf.all.log_martians records packets with impossible source addresses, providing early warning of spoofing and misconfiguration.

| Field | Value |
| --- | --- |
| Check | `sysctl` |
| Parameters | `{key: net.ipv4.conf.all.log_martians, value: '1'}` |
| Tags | `kernel`, `network`, `logging` |
| Automated fix | yes |
| Fix type | `sysctl_set` |

Remediation: Set net.ipv4.conf.all.log_martians = 1.

### AEGIS-0025

**Reverse path filtering is disabled**

`AEGIS-0025` | severity `medium` | category Kernel | CIS Ubuntu Linux 22.04 3.2.7

Strict reverse path filtering drops packets whose source address would not be routed back through the receiving interface, mitigating address spoofing.

| Field | Value |
| --- | --- |
| Check | `sysctl` |
| Parameters | `{key: net.ipv4.conf.all.rp_filter, value: '1'}` |
| Tags | `kernel`, `network`, `spoofing` |
| Automated fix | yes |
| Fix type | `sysctl_set` |

Remediation: Set net.ipv4.conf.all.rp_filter = 1.

### AEGIS-0026

**TCP SYN cookies are disabled**

`AEGIS-0026` | severity `medium` | category Kernel | CIS Ubuntu Linux 22.04 3.2.8

SYN cookies allow the host to keep serving legitimate connections during a SYN flood instead of exhausting the backlog.

| Field | Value |
| --- | --- |
| Check | `sysctl` |
| Parameters | `{key: net.ipv4.tcp_syncookies, value: '1'}` |
| Tags | `kernel`, `network`, `dos` |
| Automated fix | yes |
| Fix type | `sysctl_set` |

Remediation: Set net.ipv4.tcp_syncookies = 1.

### AEGIS-0027

**IPv6 router advertisements are accepted**

`AEGIS-0027` | severity `medium` | category Kernel | CIS Ubuntu Linux 22.04 3.2.9

Hosts that do not rely on IPv6 autoconfiguration should ignore router advertisements, preventing rogue routers from changing default routes.

| Field | Value |
| --- | --- |
| Check | `sysctl` |
| Parameters | `{key: net.ipv6.conf.all.accept_ra, value: '0'}` |
| Tags | `kernel`, `network`, `ipv6` |
| Automated fix | yes |
| Fix type | `sysctl_set` |

Remediation: Set net.ipv6.conf.all.accept_ra = 0 where IPv6 autoconfiguration is not used.

### AEGIS-0028

**The cramfs kernel module is available**

`AEGIS-0028` | severity `medium` | category Kernel | CIS Ubuntu Linux 22.04 1.1.1.1

cramfs is rarely required on modern servers. Blocking the module reduces the kernel filesystem attack surface available to local attackers.

| Field | Value |
| --- | --- |
| Check | `kernel_module` |
| Parameters | `{module: cramfs, state: disabled}` |
| Tags | `kernel`, `modules`, `filesystems` |
| Automated fix | no |

Remediation: Add "install cramfs /bin/false" to a file in /etc/modprobe.d and run modprobe -r cramfs.

```sh
printf 'install cramfs /bin/false\n' > /etc/modprobe.d/cramfs.conf
```

### AEGIS-0029

**The freevxfs kernel module is available**

`AEGIS-0029` | severity `medium` | category Kernel | CIS Ubuntu Linux 22.04 1.1.1.2

The freevxfs filesystem is obsolete and unnecessary on managed Linux hosts.

| Field | Value |
| --- | --- |
| Check | `kernel_module` |
| Parameters | `{module: freevxfs, state: disabled}` |
| Tags | `kernel`, `modules`, `filesystems` |
| Automated fix | no |

Remediation: Add "install freevxfs /bin/false" to /etc/modprobe.d.

```sh
printf 'install freevxfs /bin/false\n' > /etc/modprobe.d/freevxfs.conf
```

### AEGIS-0030

**The udf kernel module is available**

`AEGIS-0030` | severity `medium` | category Kernel | CIS Ubuntu Linux 22.04 1.1.1.6

UDF is used for optical media and is not normally needed on a server. Loading unneeded filesystem drivers expands the reachable kernel attack surface.

| Field | Value |
| --- | --- |
| Check | `kernel_module` |
| Parameters | `{module: udf, state: disabled}` |
| Tags | `kernel`, `modules`, `filesystems` |
| Automated fix | no |

Remediation: Add "install udf /bin/false" to /etc/modprobe.d.

```sh
printf 'install udf /bin/false\n' > /etc/modprobe.d/udf.conf
```

### AEGIS-0031

**The SCTP kernel module is available**

`AEGIS-0031` | severity `medium` | category Kernel | CIS Ubuntu Linux 22.04 3.3.2

SCTP is not commonly used and has a history of kernel bugs. Disabling the protocol module removes that code path from local and container workloads.

| Field | Value |
| --- | --- |
| Check | `kernel_module` |
| Parameters | `{module: sctp, state: disabled}` |
| Tags | `kernel`, `modules`, `network` |
| Automated fix | no |

Remediation: Add "install sctp /bin/false" to /etc/modprobe.d and remove any explicit load.

```sh
printf 'install sctp /bin/false\n' > /etc/modprobe.d/sctp.conf
```

### AEGIS-0032

**/etc/passwd permissions are too broad**

`AEGIS-0032` | severity `high` | category Filesystem | CIS Ubuntu Linux 22.04 6.1.1

/etc/passwd must be world-readable but writable only by root. Broader write access allows account manipulation and privilege escalation.

| Field | Value |
| --- | --- |
| Check | `file_mode` |
| Parameters | `{max_mode: '0644', missing: fail, path: /etc/passwd}` |
| Tags | `filesystem`, `permissions`, `accounts` |
| Automated fix | yes |
| Fix type | `file_mode` |

Remediation: Set /etc/passwd ownership root:root and mode 0644.

```sh
chmod 644 /etc/passwd && chown root:root /etc/passwd
```

### AEGIS-0033

**/etc/group permissions are too broad**

`AEGIS-0033` | severity `high` | category Filesystem | CIS Ubuntu Linux 22.04 6.1.3

/etc/group must be writable only by root. Unauthorized changes can grant group-based access to sensitive resources.

| Field | Value |
| --- | --- |
| Check | `file_mode` |
| Parameters | `{max_mode: '0644', missing: fail, path: /etc/group}` |
| Tags | `filesystem`, `permissions`, `accounts` |
| Automated fix | yes |
| Fix type | `file_mode` |

Remediation: Set /etc/group ownership root:root and mode 0644.

```sh
chmod 644 /etc/group && chown root:root /etc/group
```

### AEGIS-0034

**/etc/shadow is accessible to non-root users**

`AEGIS-0034` | severity `critical` | category Filesystem | CIS Ubuntu Linux 22.04 6.1.5

Password hashes in /etc/shadow must not be readable by unprivileged users. Offline cracking of leaked hashes is usually trivial for weak passwords.

| Field | Value |
| --- | --- |
| Check | `file_mode` |
| Parameters | `{max_mode: '0640', missing: fail, path: /etc/shadow}` |
| Tags | `filesystem`, `permissions`, `passwords` |
| Automated fix | yes |
| Fix type | `file_mode` |

Remediation: Set /etc/shadow ownership root:shadow and mode 0640.

```sh
chmod 640 /etc/shadow && chown root:shadow /etc/shadow
```

### AEGIS-0035

**/etc/shadow- backup is accessible to non-root users**

`AEGIS-0035` | severity `high` | category Filesystem | CIS Ubuntu Linux 22.04 6.1.6

The previous shadow database has the same sensitivity as the live file and must not be readable by unprivileged users.

| Field | Value |
| --- | --- |
| Check | `file_mode` |
| Parameters | `{max_mode: '0640', missing: fail, path: /etc/shadow-}` |
| Tags | `filesystem`, `permissions`, `passwords` |
| Automated fix | yes |
| Fix type | `file_mode` |

Remediation: Set /etc/shadow- ownership root:shadow and mode 0640.

```sh
chmod 640 /etc/shadow- && chown root:shadow /etc/shadow-
```

### AEGIS-0036

**/etc/gshadow is accessible to non-root users**

`AEGIS-0036` | severity `high` | category Filesystem | CIS Ubuntu Linux 22.04 6.1.7

/etc/gshadow stores group password hashes and administrative membership and must be restricted to root and the shadow group.

| Field | Value |
| --- | --- |
| Check | `file_mode` |
| Parameters | `{max_mode: '0640', missing: fail, path: /etc/gshadow}` |
| Tags | `filesystem`, `permissions`, `groups` |
| Automated fix | yes |
| Fix type | `file_mode` |

Remediation: Set /etc/gshadow ownership root:shadow and mode 0640.

```sh
chmod 640 /etc/gshadow && chown root:shadow /etc/gshadow
```

### AEGIS-0037

**World-writable files exist**

`AEGIS-0037` | severity `high` | category Filesystem | CIS Ubuntu Linux 22.04 6.1.9

Any regular file writable by every local user can be used to tamper with configuration, inject code, or disrupt services. World-writable files should be limited to explicitly managed temporary locations.

| Field | Value |
| --- | --- |
| Check | `world_writable` |
| Parameters | `{exclude_dirs: [proc, sys, dev, run], max_depth: 8, max_entries: 50000, root: /}` |
| Tags | `filesystem`, `permissions`, `integrity` |
| Automated fix | no |

Remediation: Identify each reported path, remove world-write permission, and determine how it was created.

```sh
find / -xdev -type f -perm -0002 -print 2>/dev/null
```

### AEGIS-0038

**Cron configuration permissions are too permissive**

`AEGIS-0038` | severity `high` | category Filesystem | CIS Ubuntu Linux 22.04 5.1.2

/etc/crontab and /etc/cron.* directories execute commands as root. They must be owned by root and writable only by root.

| Field | Value |
| --- | --- |
| Check | `cron_permissions` |
| Parameters | `{kind: permissions}` |
| Tags | `filesystem`, `permissions`, `cron` |
| Automated fix | no |

Remediation: Set /etc/crontab to 0600 and /etc/cron.* directories to 0700, all owned by root.

```sh
chmod 600 /etc/crontab; chmod 700 /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly
```

### AEGIS-0039

**Cron and at are not restricted by allow lists**

`AEGIS-0039` | severity `high` | category Filesystem | CIS Ubuntu Linux 22.04 5.1.8

Without cron.allow and at.allow, any local user may schedule jobs. Explicit allow lists limit those facilities to trusted administrators.

| Field | Value |
| --- | --- |
| Check | `cron_permissions` |
| Parameters | `{kind: restricted}` |
| Tags | `filesystem`, `permissions`, `cron` |
| Automated fix | no |

Remediation: Create /etc/cron.allow and /etc/at.allow containing only authorized users, and remove the deny files.

```sh
printf 'root\n' > /etc/cron.allow; printf 'root\n' > /etc/at.allow; rm -f /etc/cron.deny /etc/at.deny
```

### AEGIS-0040

**/tmp is missing nodev, nosuid, or noexec mount options**

`AEGIS-0040` | severity `high` | category Filesystem | CIS Ubuntu Linux 22.04 1.1.2.2-1.1.2.4

A separate /tmp with nodev, nosuid, and noexec prevents execution of dropped binaries and blocks device or setuid abuse from a world-writable location.

| Field | Value |
| --- | --- |
| Check | `mount_option` |
| Parameters | `{missing: fail, mountpoint: /tmp, options: [nodev, nosuid, noexec]}` |
| Tags | `filesystem`, `mounts`, `tmp` |
| Automated fix | no |

Remediation: Add nodev,nosuid,noexec to the /tmp entry in /etc/fstab and remount it.

```sh
mount -o remount,nodev,nosuid,noexec /tmp
```

### AEGIS-0041

**/dev/shm is missing nodev, nosuid, or noexec mount options**

`AEGIS-0041` | severity `high` | category Filesystem | CIS Ubuntu Linux 22.04 1.1.3

Shared memory is a common staging area for exploits. Restricting execution and device nodes there raises the cost of post-exploitation.

| Field | Value |
| --- | --- |
| Check | `mount_option` |
| Parameters | `{missing: fail, mountpoint: /dev/shm, options: [nodev, nosuid, noexec]}` |
| Tags | `filesystem`, `mounts`, `shm` |
| Automated fix | no |

Remediation: Add nodev,nosuid,noexec to the /dev/shm entry in /etc/fstab and remount it.

```sh
mount -o remount,nodev,nosuid,noexec /dev/shm
```

### AEGIS-0042

**More than one account has UID 0**

`AEGIS-0042` | severity `critical` | category Accounts | CIS Ubuntu Linux 22.04 6.2.3

UID 0 is the superuser. Every additional UID 0 account is an unlogged backdoor that bypasses accountability and role separation.

| Field | Value |
| --- | --- |
| Check | `account` |
| Parameters | `{kind: uid_zero_unique}` |
| Tags | `accounts`, `privilege` |
| Automated fix | no |

Remediation: Remove or reassign every UID 0 account other than root after reviewing its ownership.

```sh
awk -F: '($3 == 0) {print $1}' /etc/passwd
```

### AEGIS-0043

**Accounts with empty password fields exist**

`AEGIS-0043` | severity `critical` | category Accounts | CIS Ubuntu Linux 22.04 6.2.2

An empty password hash permits passwordless login on every service that consults PAM or the shadow database.

| Field | Value |
| --- | --- |
| Check | `account` |
| Parameters | `{kind: empty_password}` |
| Tags | `accounts`, `passwords` |
| Automated fix | no |

Remediation: Lock each affected account immediately, then set a strong password or disable the account.

```sh
awk -F: '($2 == "") {print $1}' /etc/shadow
```

### AEGIS-0044

**Accounts are not using shadowed passwords**

`AEGIS-0044` | severity `high` | category Accounts | CIS Ubuntu Linux 22.04 6.2.1

Password hashes must live in /etc/shadow. A hash in /etc/passwd is readable by every local user and can be cracked offline.

| Field | Value |
| --- | --- |
| Check | `account` |
| Parameters | `{kind: shadowed_passwords}` |
| Tags | `accounts`, `passwords` |
| Automated fix | no |

Remediation: Run pwconv to migrate password hashes into /etc/shadow and verify every passwd entry uses x.

```sh
pwconv
```

### AEGIS-0045

**System accounts have unlocked passwords**

`AEGIS-0045` | severity `high` | category Accounts | CIS Ubuntu Linux 22.04 5.5.2

Service accounts below UID 1000 must not be able to authenticate. Their shadow entries should begin with ! or * unless a documented exception exists.

| Field | Value |
| --- | --- |
| Check | `account` |
| Parameters | `{kind: system_accounts_locked}` |
| Tags | `accounts`, `service-accounts` |
| Automated fix | no |

Remediation: Lock system accounts with usermod -L or set the shadow password field to ! for each reported service account.

```sh
awk -F: '($3 < 1000 && $3 != 0) {print $1}' /etc/passwd
```

### AEGIS-0046

**The root account does not have a valid login shell**

`AEGIS-0046` | severity `medium` | category Accounts | CIS Ubuntu Linux 22.04 5.5.2 (root account)

Root must retain a usable, absolute login shell for emergency recovery. An invalid or unlisted shell can prevent administrators from repairing a host.

| Field | Value |
| --- | --- |
| Check | `account` |
| Parameters | `{kind: root_shell_valid}` |
| Tags | `accounts`, `root` |
| Automated fix | no |

Remediation: Set root's shell to a valid entry from /etc/shells, normally /bin/bash.

```sh
chsh -s /bin/bash root
```

### AEGIS-0047

**Duplicate UIDs exist**

`AEGIS-0047` | severity `high` | category Accounts | CIS Ubuntu Linux 22.04 6.2.14

Duplicate UIDs make file ownership ambiguous and can hide a second account with another user's privileges.

| Field | Value |
| --- | --- |
| Check | `account` |
| Parameters | `{kind: duplicate_uid}` |
| Tags | `accounts`, `identity` |
| Automated fix | no |

Remediation: Resolve duplicate UIDs by assigning a unique UID and reconciling file ownership.

```sh
awk -F: '{print $3}' /etc/passwd | sort | uniq -d
```

### AEGIS-0048

**Login users have missing home directories**

`AEGIS-0048` | severity `medium` | category Accounts | CIS Ubuntu Linux 22.04 6.2.5

A missing home directory breaks login, hides user data, and can cause services to fall back to unsafe working directories.

| Field | Value |
| --- | --- |
| Check | `account` |
| Parameters | `{kind: home_exists}` |
| Tags | `accounts`, `home` |
| Automated fix | no |

Remediation: Create each missing home directory with the correct owner and mode, or disable the account.

```sh
awk -F: '($3 >= 1000) {print $1, $6}' /etc/passwd
```

### AEGIS-0049

**User home directories are more permissive than 0750**

`AEGIS-0049` | severity `medium` | category Accounts | CIS Ubuntu Linux 22.04 6.2.6

Home directories should not be readable or writable by other unprivileged users. Group and world access can leak shell history, keys, and application data.

| Field | Value |
| --- | --- |
| Check | `account` |
| Parameters | `{kind: home_permissions, max_mode: '0750'}` |
| Tags | `accounts`, `permissions`, `home` |
| Automated fix | no |

Remediation: Set each home directory to mode 0750 or more restrictive.

```sh
chmod 750 /home/*
```

### AEGIS-0050

**Password aging exceeds policy**

`AEGIS-0050` | severity `high` | category Accounts | CIS Ubuntu Linux 22.04 5.5.1.2

Login accounts must expire passwords within 365 days and warn at least seven days before expiry. Non-expiring passwords increase the value of a leaked hash.

| Field | Value |
| --- | --- |
| Check | `account` |
| Parameters | `{kind: password_expiry, max_days: 365}` |
| Tags | `accounts`, `passwords`, `aging` |
| Automated fix | no |

Remediation: Set PASS_MAX_DAYS 365, PASS_WARN_AGE 7, and PASS_MIN_DAYS 1 for each login account.

```sh
chage --maxdays 365 --warndays 7 --mindays 1 root
```

### AEGIS-0051

**Inactive accounts are not locked after thirty days**

`AEGIS-0051` | severity `medium` | category Accounts | CIS Ubuntu Linux 22.04 5.5.1.4

An account that remains inactive should be locked automatically so abandoned credentials cannot be used indefinitely.

| Field | Value |
| --- | --- |
| Check | `account` |
| Parameters | `{kind: inactive_lock, max_days: 30}` |
| Tags | `accounts`, `passwords`, `lockout` |
| Automated fix | no |

Remediation: Set the inactive field to 30 days for every login account.

```sh
chage --inactive 30 root
```

### AEGIS-0052

**login.defs PASS_MAX_DAYS exceeds 365**

`AEGIS-0052` | severity `high` | category Accounts | CIS Ubuntu Linux 22.04 5.5.1.2

The default maximum password age applies to new accounts and must not exceed one year.

| Field | Value |
| --- | --- |
| Check | `login_defs` |
| Parameters | `{key: PASS_MAX_DAYS, max: 365}` |
| Tags | `accounts`, `passwords`, `login-defs` |
| Automated fix | yes |
| Fix type | `login_defs_set` |

Remediation: Set PASS_MAX_DAYS 365 in /etc/login.defs.

### AEGIS-0053

**login.defs PASS_MIN_DAYS is below one**

`AEGIS-0053` | severity `medium` | category Accounts | CIS Ubuntu Linux 22.04 5.5.1.1

A minimum password age prevents users from cycling through passwords to return to a previously used credential.

| Field | Value |
| --- | --- |
| Check | `login_defs` |
| Parameters | `{key: PASS_MIN_DAYS, min: 1}` |
| Tags | `accounts`, `passwords`, `login-defs` |
| Automated fix | yes |
| Fix type | `login_defs_set` |

Remediation: Set PASS_MIN_DAYS 1 in /etc/login.defs.

### AEGIS-0054

**login.defs PASS_WARN_AGE is below seven days**

`AEGIS-0054` | severity `medium` | category Accounts | CIS Ubuntu Linux 22.04 5.5.1.3

Users need advance notice of password expiry to avoid lockouts and rushed credential choices.

| Field | Value |
| --- | --- |
| Check | `login_defs` |
| Parameters | `{key: PASS_WARN_AGE, min: 7}` |
| Tags | `accounts`, `passwords`, `login-defs` |
| Automated fix | yes |
| Fix type | `login_defs_set` |

Remediation: Set PASS_WARN_AGE 7 in /etc/login.defs.

### AEGIS-0055

**Default user umask is less restrictive than 027**

`AEGIS-0055` | severity `medium` | category Accounts | CIS Ubuntu Linux 22.04 5.5.4

A umask of 027 prevents new files from being group-writable and hides them from other users. A permissive default silently exposes newly created data.

| Field | Value |
| --- | --- |
| Check | `login_defs` |
| Parameters | `{key: UMASK, requires_bits: '027'}` |
| Tags | `accounts`, `umask`, `login-defs` |
| Automated fix | yes |
| Fix type | `login_defs_set` |

Remediation: Set UMASK 027 in /etc/login.defs and review shell or PAM umask overrides.

### AEGIS-0056

**Password minimum length is below fourteen characters**

`AEGIS-0056` | severity `high` | category Accounts | CIS Ubuntu Linux 22.04 5.4.1

Long passwords are the most effective defence against offline cracking. A minimum length of 14 characters is required by the benchmark and is practical with passphrases.

| Field | Value |
| --- | --- |
| Check | `password_quality` |
| Parameters | `{key: minlen, min: 14}` |
| Tags | `accounts`, `passwords`, `pwquality` |
| Automated fix | yes |
| Fix type | `pwquality_set` |

Remediation: Set minlen = 14 in /etc/security/pwquality.conf.

### AEGIS-0057

**Password complexity requires fewer than four character classes**

`AEGIS-0057` | severity `medium` | category Accounts | CIS Ubuntu Linux 22.04 5.4.1

minclass controls how many of lowercase, uppercase, digits, and symbols must appear. Requiring all four classes increases the search space for human-chosen passwords.

| Field | Value |
| --- | --- |
| Check | `password_quality` |
| Parameters | `{key: minclass, min: 4}` |
| Tags | `accounts`, `passwords`, `pwquality` |
| Automated fix | yes |
| Fix type | `pwquality_set` |

Remediation: Set minclass = 4 in /etc/security/pwquality.conf.

### AEGIS-0058

**Password quality enforcement is not enabled**

`AEGIS-0058` | severity `medium` | category Accounts | CIS Ubuntu Linux 22.04 5.4.1

pwquality only blocks weak passwords when enforcing = 1. Otherwise weak passwords produce warnings but are still accepted.

| Field | Value |
| --- | --- |
| Check | `password_quality` |
| Parameters | `{exact: '1', key: enforcing}` |
| Tags | `accounts`, `passwords`, `pwquality` |
| Automated fix | yes |
| Fix type | `pwquality_set` |

Remediation: Set enforcing = 1 in /etc/security/pwquality.conf.

### AEGIS-0059

**PAM does not invoke pam_pwquality**

`AEGIS-0059` | severity `high` | category Accounts | CIS Ubuntu Linux 22.04 5.4.1

Password quality settings have no effect unless the PAM password stack calls pam_pwquality.so. The module must appear in the password stack of the common password configuration.

| Field | Value |
| --- | --- |
| Check | `file_content` |
| Parameters | `{missing: fail, path: /etc/pam.d/common-password, pattern: '(?m)^\s*password\s+\S+\s+pam_pwquality\.so',   state: present}` |
| Tags | `accounts`, `passwords`, `pam` |
| Automated fix | no |

Remediation: Add pam_pwquality.so to the password stack in /etc/pam.d/common-password using pam-auth-update or your distribution's supported method.

```sh
grep -n pam_pwquality /etc/pam.d/common-password
```

### AEGIS-0060

**auditd is not installed**

`AEGIS-0060` | severity `high` | category Logging | CIS Ubuntu Linux 22.04 4.1.1.1

The Linux audit subsystem records security-relevant system calls and events. Without auditd, forensic evidence for privilege escalation and file tampering is lost.

| Field | Value |
| --- | --- |
| Check | `auditd` |
| Parameters | `{kind: installed}` |
| Tags | `logging`, `auditd` |
| Automated fix | no |

Remediation: Install the auditd package and enable a baseline audit rule set.

```sh
apt-get install auditd audispd-plugins
```

### AEGIS-0061

**auditd is not enabled at boot**

`AEGIS-0061` | severity `high` | category Logging | CIS Ubuntu Linux 22.04 4.1.1.2

An installed but disabled audit daemon provides no evidence after a reboot. auditd must be enabled in systemd and started.

| Field | Value |
| --- | --- |
| Check | `auditd` |
| Parameters | `{kind: service}` |
| Tags | `logging`, `auditd`, `services` |
| Automated fix | no |

Remediation: Enable and start auditd.

```sh
systemctl --now enable auditd
```

### AEGIS-0062

**auditd deletes logs when the disk fills**

`AEGIS-0062` | severity `high` | category Logging | CIS Ubuntu Linux 22.04 4.1.2.2

max_log_file_action must be keep_logs. Rotating or deleting audit logs under pressure lets an attacker erase evidence by filling the filesystem.

| Field | Value |
| --- | --- |
| Check | `auditd` |
| Parameters | `{exact: keep_logs, key: max_log_file_action, kind: config, path: /etc/audit/auditd.conf}` |
| Tags | `logging`, `auditd`, `retention` |
| Automated fix | no |

Remediation: Set max_log_file_action = keep_logs in /etc/audit/auditd.conf.

### AEGIS-0063

**auditd does not warn by email when logs run low**

`AEGIS-0063` | severity `medium` | category Logging | CIS Ubuntu Linux 22.04 4.1.2.4

space_left_action should notify administrators before the audit filesystem is exhausted, providing time to preserve or expand storage.

| Field | Value |
| --- | --- |
| Check | `auditd` |
| Parameters | `{allowed: [email], key: space_left_action, kind: config, path: /etc/audit/auditd.conf}` |
| Tags | `logging`, `auditd`, `alerting` |
| Automated fix | no |

Remediation: Set space_left_action = email and configure a working mail transfer agent.

### AEGIS-0064

**Kernel auditing is not enabled at boot**

`AEGIS-0064` | severity `medium` | category Logging | CIS Ubuntu Linux 22.04 4.1.3

audit=1 on the kernel command line ensures early boot events are captured before the audit daemon starts.

| Field | Value |
| --- | --- |
| Check | `auditd` |
| Parameters | `{kind: grub}` |
| Tags | `logging`, `auditd`, `boot` |
| Automated fix | no |

Remediation: Add audit=1 to GRUB_CMDLINE_LINUX in /etc/default/grub and regenerate the boot configuration.

```sh
update-grub
```

### AEGIS-0065

**Journald storage is not persistent**

`AEGIS-0065` | severity `medium` | category Logging | CIS Ubuntu Linux 22.04 4.2.1.4

With volatile storage, journal entries disappear at reboot. Persisting them provides continuity with auditd and supports incident reconstruction.

| Field | Value |
| --- | --- |
| Check | `file_content` |
| Parameters | `{missing: fail, path: /etc/systemd/journald.conf, pattern: '(?m)^\s*Storage\s*=\s*persistent\s*$',   state: present}` |
| Tags | `logging`, `journald` |
| Automated fix | no |

Remediation: Set Storage=persistent in /etc/systemd/journald.conf and restart systemd-journald.

```sh
systemctl restart systemd-journald
```

### AEGIS-0066

**System log file permissions are too broad**

`AEGIS-0066` | severity `medium` | category Logging | CIS Ubuntu Linux 22.04 4.2.3

Logs can contain usernames, network addresses, and command fragments. They must not be readable by every local user.

| Field | Value |
| --- | --- |
| Check | `file_mode` |
| Parameters | `{max_mode: '0640', missing: fail, path: /var/log/syslog}` |
| Tags | `logging`, `permissions` |
| Automated fix | yes |
| Fix type | `file_mode` |

Remediation: Set system log files to mode 0640 and ownership root:adm or root:root.

```sh
chmod 640 /var/log/syslog
```

### AEGIS-0067

**The UFW host firewall is not enabled**

`AEGIS-0067` | severity `high` | category Firewall | CIS Ubuntu Linux 22.04 3.5.1.2

A host firewall limits inbound exposure to services that are intentionally published. UFW must be enabled for its default policy to take effect.

| Field | Value |
| --- | --- |
| Check | `firewall` |
| Parameters | `{engine: ufw, setting: enabled}` |
| Tags | `firewall`, `ufw` |
| Automated fix | no |

Remediation: Enable UFW after confirming management access will not be locked out.

```sh
ufw --force enable
```

### AEGIS-0068

**UFW default inbound policy is not deny**

`AEGIS-0068` | severity `high` | category Firewall | CIS Ubuntu Linux 22.04 3.5.1.3

The default incoming policy must drop or reject traffic that is not explicitly allowed. A permissive default exposes every listening service.

| Field | Value |
| --- | --- |
| Check | `firewall` |
| Parameters | `{engine: ufw, setting: default_incoming}` |
| Tags | `firewall`, `ufw`, `default-policy` |
| Automated fix | no |

Remediation: Set DEFAULT_INPUT_POLICY="DROP" in /etc/default/ufw and reload the firewall.

```sh
ufw default deny incoming && ufw reload
```

### AEGIS-0069

**No supported host firewall is enabled**

`AEGIS-0069` | severity `high` | category Firewall | CIS Ubuntu Linux 22.04 3.5 (host-based firewall)

At least one of UFW, firewalld, or nftables must enforce an inbound policy. Workloads on cloud networks still need host-level filtering for defence in depth.

| Field | Value |
| --- | --- |
| Check | `firewall` |
| Parameters | `{engine: any, setting: enabled}` |
| Tags | `firewall`, `defence-in-depth` |
| Automated fix | no |

Remediation: Enable UFW, firewalld, or an equivalent nftables policy with a default-deny input chain.

```sh
ufw status verbose
```

### AEGIS-0070

**A telnet server is installed**

`AEGIS-0070` | severity `high` | category Packages | CIS Distribution Independent Linux 2.2 (legacy network services)

Telnet transmits credentials and session data in clear text and has no place on a hardened host. Remove the server package and use SSH instead.

| Field | Value |
| --- | --- |
| Check | `package` |
| Parameters | `{name: [telnetd, telnet-server, inetutils-telnetd], state: removed}` |
| Tags | `packages`, `telnet`, `legacy` |
| Automated fix | no |

Remediation: Remove every installed telnet server package.

```sh
apt-get remove --purge telnetd inetutils-telnetd telnet-server
```

### AEGIS-0071

**An rsh server is installed**

`AEGIS-0071` | severity `high` | category Packages | CIS Distribution Independent Linux 2.3 (rsh services)

rsh and rlogin trust host-based authentication and send data without encryption. They are unsuitable for any modern environment.

| Field | Value |
| --- | --- |
| Check | `package` |
| Parameters | `{name: [rsh-server, rsh], state: removed}` |
| Tags | `packages`, `rsh`, `legacy` |
| Automated fix | no |

Remediation: Remove the rsh server package.

```sh
apt-get remove --purge rsh-server rsh
```

### AEGIS-0072

**A TFTP server is installed**

`AEGIS-0072` | severity `high` | category Packages | CIS Distribution Independent Linux 2.2 (tftp services)

TFTP provides unauthenticated file transfer and is frequently abused for staging payloads or exfiltrating data. It should not be installed without a documented requirement.

| Field | Value |
| --- | --- |
| Check | `package` |
| Parameters | `{name: [tftpd-hpa, tftp-server, atftpd], state: removed}` |
| Tags | `packages`, `tftp`, `legacy` |
| Automated fix | no |

Remediation: Remove the TFTP server package unless it is an approved, isolated requirement.

```sh
apt-get remove --purge tftpd-hpa atftpd tftp-server
```

### AEGIS-0073

**xinetd is installed**

`AEGIS-0073` | severity `medium` | category Packages | CIS Ubuntu Linux 22.04 2.2.1

xinetd starts legacy network services on demand and often exposes services that are otherwise disabled. Managed hosts should not run it.

| Field | Value |
| --- | --- |
| Check | `package` |
| Parameters | `{name: xinetd, state: removed}` |
| Tags | `packages`, `xinetd`, `legacy` |
| Automated fix | no |

Remediation: Remove xinetd and migrate any required service to a supervised systemd unit.

```sh
apt-get remove --purge xinetd
```

### AEGIS-0074

**Automatic security updates are not installed**

`AEGIS-0074` | severity `medium` | category Packages | CIS Ubuntu Linux 22.04 1.9

Timely patching is the highest-value control against known exploitation. unattended-upgrades (Debian/Ubuntu) or dnf-automatic (RPM distributions) applies security updates without waiting for an operator.

| Field | Value |
| --- | --- |
| Check | `package` |
| Parameters | `{name: [unattended-upgrades, dnf-automatic], state: installed}` |
| Tags | `packages`, `updates`, `patching` |
| Automated fix | no |

Remediation: Install and configure automatic security updates, then verify the timer or service is active.

```sh
apt-get install unattended-upgrades && dpkg-reconfigure --priority=low unattended-upgrades
```

### AEGIS-0075

**The cron daemon is not enabled**

`AEGIS-0075` | severity `medium` | category Services | CIS Ubuntu Linux 22.04 5.1.1

Scheduled maintenance and security jobs depend on cron. Disabling it silently stops rotation, backup, and patch tasks.

| Field | Value |
| --- | --- |
| Check | `service` |
| Parameters | `{name: cron, state: enabled}` |
| Tags | `services`, `cron` |
| Automated fix | no |

Remediation: Enable and start cron.

```sh
systemctl --now enable cron
```

### AEGIS-0076

**The SSH service is not enabled**

`AEGIS-0076` | severity `medium` | category Services | CIS Ubuntu Linux 22.04 5.3 (SSH service)

Administrative access should be available after reboot through the audited SSH service. An unexpectedly disabled SSH unit can indicate tampering.

| Field | Value |
| --- | --- |
| Check | `service` |
| Parameters | `{name: ssh, state: enabled}` |
| Tags | `services`, `ssh` |
| Automated fix | no |

Remediation: Enable and start ssh.

```sh
systemctl --now enable ssh
```

### AEGIS-0077

**The telnet socket is enabled**

`AEGIS-0077` | severity `high` | category Services | CIS Distribution Independent Linux 2.2 (telnet services)

systemd socket activation can expose telnet even when no inetd process is running. The socket must be disabled and masked.

| Field | Value |
| --- | --- |
| Check | `service` |
| Parameters | `{name: telnet.socket, state: disabled}` |
| Tags | `services`, `telnet`, `socket` |
| Automated fix | no |

Remediation: Disable and mask the telnet socket, then remove the server package.

```sh
systemctl disable --now telnet.socket && systemctl mask telnet.socket
```

### AEGIS-0078

**The rsh socket is enabled**

`AEGIS-0078` | severity `high` | category Services | CIS Distribution Independent Linux 2.3 (rsh services)

rsh socket activation exposes unauthenticated remote shell access and must not be enabled.

| Field | Value |
| --- | --- |
| Check | `service` |
| Parameters | `{name: rsh.socket, state: disabled}` |
| Tags | `services`, `rsh`, `socket` |
| Automated fix | no |

Remediation: Disable and mask the rsh socket.

```sh
systemctl disable --now rsh.socket && systemctl mask rsh.socket
```

### AEGIS-0079

**The tftp socket is enabled**

`AEGIS-0079` | severity `medium` | category Services | CIS Distribution Independent Linux 2.2 (tftp services)

TFTP socket activation makes an unauthenticated file transfer service reachable without an administrator starting it explicitly.

| Field | Value |
| --- | --- |
| Check | `service` |
| Parameters | `{name: tftp.socket, state: disabled}` |
| Tags | `services`, `tftp`, `socket` |
| Automated fix | no |

Remediation: Disable and mask the tftp socket.

```sh
systemctl disable --now tftp.socket && systemctl mask tftp.socket
```

### AEGIS-0080

**Legacy clear-text or unauthenticated ports are listening**

`AEGIS-0080` | severity `high` | category Services | CIS Distribution Independent Linux 2.2-2.3 (legacy services)

FTP, telnet, TFTP, rpcbind, and rsh-family services transmit credentials or data without adequate protection. They must not accept network connections on a hardened host.

| Field | Value |
| --- | --- |
| Check | `listening_port` |
| Parameters | `{ignore_loopback: false, mode: denied, ports: [21, 23, 69, 111, 512, 513, 514]}` |
| Tags | `services`, `ports`, `legacy` |
| Automated fix | no |

Remediation: Stop the owning service or socket unit, remove its package, and confirm with ss -lntup.

```sh
ss -lntup
```

### AEGIS-0081

**The SSH warning banner file is missing**

`AEGIS-0081` | severity `low` | category SSH | CIS Ubuntu Linux 22.04 5.3.18

sshd references /etc/issue.net through the Banner directive. If the file is absent, remote users see no legal warning before authentication.

| Field | Value |
| --- | --- |
| Check | `file_exists` |
| Parameters | `{kind: file, path: /etc/issue.net, state: present}` |
| Tags | `ssh`, `banner` |
| Automated fix | no |

Remediation: Create /etc/issue.net with an approved warning and ensure sshd_config sets Banner /etc/issue.net.

```sh
printf 'Authorized use only.\n' > /etc/issue.net
```

## Check types

Checks are read-only and operate through the audit root. Absolute symlinks inside the root are resolved relative to that root, never to the host, so an image can be audited safely from a build server.

| Check | What it inspects |
| --- | --- |
| `file_exists` | Presence and expected type of a path. |
| `file_mode` | Maximum permission bits (and optionally ownership) of a file. |
| `file_owner` | Owning user and group of a path. |
| `file_content` | Required or forbidden patterns in a text file, with line reporting. |
| `sysctl` | Effective sysctl value across the scanned sysctl configuration files. |
| `sshd` | Effective sshd_config keyword, including first-match and Match section handling. |
| `package` | Installed package state through distro package databases. |
| `service` | systemd unit enablement and mask state from unit symlinks. |
| `account` | passwd, shadow and group invariants for local accounts. |
| `mount_option` | Required mount options for a mount point in fstab and mountinfo. |
| `firewall` | UFW, firewalld and nftables configuration state. |
| `kernel_module` | Whether a module is disabled through modprobe.d. |
| `login_defs` | login.defs policy values with numeric or set comparisons. |
| `auditd` | auditd.conf settings and audit daemon availability. |
| `cron_permissions` | Modes of crontab, cron directories and at configuration. |
| `world_writable` | World-writable files below a path, with bounded traversal. |
| `listening_port` | Listening sockets from procfs, including socket ownership. |
| `password_quality` | pwquality.conf enforcement, length and complexity settings. |

The bundled pack exercises 17 of these 18 checks. `file_owner` is implemented and unit-tested but not used by the default pack, because ownership of a fixture tree cannot be changed without root; the check is available to custom rule packs.
