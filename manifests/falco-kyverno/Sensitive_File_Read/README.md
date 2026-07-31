# Sensitive File Read in Container

| Property | Value |
|---|---|
| **Type** | Falco (Detection Only) |
| **Kyverno Prevention** | N/A (Runtime file action). |
| **Falco Detection** | Monitors open/read events on sensitive file extensions or path matching. |

## Description
Detects unauthorized access/reading of credentials, security files (`/etc/shadow`, `/etc/gshadow`, `/etc/master.passwd`), private keys (`.pem`, `.key`), or SSH keys inside a container.

### 🛡️ Problem Statement — What Are We Preventing?

Containers often contain or have access to sensitive credential files that are high-value targets for attackers. Reading these files is a core credential access technique that enables further compromise:

* **Password Hash Harvesting (MITRE ATT&CK: T1003.008)**: Files like `/etc/shadow` and `/etc/gshadow` contain hashed user passwords. An attacker who reads these files can perform offline brute-force or dictionary attacks to crack passwords, gaining access to user accounts on the container or — if password reuse is common — on other systems.
* **Private Key Exfiltration**: TLS private keys (`.pem`, `.key`, `.p12`, `.pfx`) used for HTTPS, mTLS, or code signing can be stolen from containers that process encrypted traffic. With a stolen private key, an attacker can decrypt captured network traffic, impersonate the service, or sign malicious code.
* **SSH Key Theft**: SSH private keys (`id_rsa`, `id_ed25519`) found inside containers enable direct SSH access to other servers and systems that trust those keys. This is a common lateral movement technique — one compromised container can yield SSH access to dozens of other systems.
* **Kubernetes Secret Exposure**: Containers may have mounted secrets at predictable paths. An attacker reading these credential files can harvest database passwords, API tokens, and cloud provider credentials that enable access to external services and data stores.
* **Supply Chain Risk**: Base images may inadvertently include credential files from the build environment. An attacker who can read the container filesystem may discover credentials that were accidentally baked into the image layer.

**Falco detects this** by monitoring file open syscalls (`open`, `openat`, `openat2`) with read access to known credential file paths and extensions inside containers, firing an `ERROR` alert while exempting legitimate processes like `sshd` and `ssh-agent` that have a valid need to access key files.


## Falco Rule Manifest
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-custom-rules
  namespace: falco
  labels:
    app.kubernetes.io/part-of: falco
    app.kubernetes.io/component: custom-rules
data:
  falco-kyverno-rules.yaml: |-
    - rule: Sensitive File Read in Container
      desc: >
        Detects access to sensitive credential files from inside a
        container.
      source: syscall
      condition: >
        evt.type in (open, openat, openat2)
        and container
        and evt.is_open_read = true
        and (fd.name in (/etc/shadow, /etc/gshadow, /etc/master.passwd)
          or fd.name endswith ".pem"
          or fd.name endswith ".key"
          or fd.name endswith ".p12"
          or fd.name endswith ".pfx"
          or fd.name contains "id_rsa"
          or fd.name contains "id_ed25519")
        and not proc.name in (sshd, ssh-agent)
      output: >
        Sensitive file read in container (file=%fd.name
        command=%proc.cmdline pod=%k8s.pod.name ns=%k8s.ns.name
        user=%user.name)
      priority: ERROR
      tags: [runtime_only, credential_access, mitre_credential_access]
```

## Detailed Explanation
#### Truth Table — Falco Runtime Detections

| `container` | `evt.is_open_read` | Target `fd.name` File | Process Excluded | Falco Alert Result |
|---|---|---|---|---|
| `true` | `true` | `/etc/hosts` | `false` | No Alert |
| `true` | `true` | `/etc/shadow` / `private.pem` / `id_rsa` | `true` (`sshd`) | No Alert |
| `true` | `true` | `/etc/shadow` / `private.pem` / `id_rsa` | `false` (`cat` / `python`) | **ALERT FIRED (ERROR)** |



### Falco Condition Breakdown

```yaml
condition: >
  evt.type in (open, openat, openat2)
  and container
  and evt.is_open_read = true
  and (fd.name in (/etc/shadow, /etc/gshadow, /etc/master.passwd)
    or fd.name endswith ".pem"
    or fd.name endswith ".key"
    or fd.name endswith ".p12"
    or fd.name endswith ".pfx"
    or fd.name contains "id_rsa"
    or fd.name contains "id_ed25519")
  and not proc.name in (sshd, ssh-agent)
```

| Falco Field | What It Does | Why It's Included |
|---|---|---|
| `evt.type in (open, openat, openat2)` | Intercepts file open syscalls. | Detects file access attempts in containers. |
| `container` | Restricts check to container processes. | Ignores host OS file access. |
| `evt.is_open_read = true` | Evaluates if file open flags include read access (`O_RDONLY` / `O_RDWR`). | Filters out write-only file opens. |
| `fd.name in (/etc/shadow, ...)` | Checks if file path targets system password/credential files. | Detects access to system hash files. |
| `fd.name endswith ".pem"` / `".key"` / `".p12"` / `".pfx"` | Checks for private key and certificate file extensions. | Detects TLS/SSL key harvesting. |
| `fd.name contains "id_rsa"` / `"id_ed25519"` | Checks for SSH private key files. | Detects SSH credential theft. |
| `not proc.name in (sshd, ssh-agent)` | Excludes legitimate SSH daemon and agent processes. | Prevents false positives from valid SSH services. |

---

### MITRE ATT&CK Mapping

| Tag | Technique | Description |
|---|---|---|
| `mitre_credential_access` | **T1003.008 — OS Credential Dumping: /etc/passwd and /etc/shadow** / **T1552.004 — Unsecured Credentials: Private Keys** | Reading shadow files or private keys allows attackers to crack passwords and steal credentials for lateral movement. |

## Test Scenarios & Manifest Examples

### 1. 🚨 RUNTIME ALERT CASE 1 — Reading `/etc/shadow`
```bash
# Attempting to read system password hashes
kubectl run test-shadow-read --image=alpine --restart=Never -it -- cat /etc/shadow
```
* **Result**: **ALERT (ERROR)** — `fd.name in (/etc/shadow, ...)` and `evt.is_open_read = true`. Falco emits `Sensitive File Read in Container`.

---

### 2. 🚨 RUNTIME ALERT CASE 2 — Reading Private Key (`.pem` / `.key`)
```bash
# Attempting to read a private key file
kubectl run test-key-read --image=alpine --restart=Never -- sh -c "touch /tmp/private.pem && cat /tmp/private.pem"
```
* **Result**: **ALERT (ERROR)** — `fd.name endswith ".pem"` matches rule condition.

---

### 3. 🛡️ EXEMPT CASE — Legitimate SSH Daemon Operation
```bash
# Process name sshd reading SSH key files
# proc.name in (sshd, ssh-agent)
```
* **Result**: **NO ALERT** — Excluded by `not proc.name in (sshd, ssh-agent)`.

---

## How to Test

### Falco (Runtime Credential Read Check)
1. Spawn a test container reading `/etc/shadow`:
```bash
kubectl run test-shadow-read --image=alpine --restart=Never -it -- cat /etc/shadow
```

2. Check Falco alerts for error alert:
```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco | grep "Sensitive file read in container"
```

3. Clean up:
```bash
kubectl delete pod test-shadow-read test-key-read --ignore-not-found
```

