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
### Falco Rule Manifest Explanation
The rule monitors syscalls requesting read access to key files:
- **`evt.is_open_read = true`**: Triggers only when a file open syscall requests read permissions.
- **`fd.name in (/etc/shadow, /etc/gshadow, /etc/master.passwd)`**: Watches core Unix credential files.
- **`fd.name endswith ".pem"` or `.key` or `.p12` or `.pfx` or contains `id_rsa`, `id_ed25519`**: Watches private key extensions.
- **`not proc.name in (sshd, ssh-agent)`**: Exempts SSH demons/agents which have a legitimate need to read keys.

## How to Test
1. Spawn a container and read `/etc/shadow` (should trigger an alert):
```bash
kubectl run test-shadow-read --image=alpine --restart=Never -it -- cat /etc/shadow
```
2. Check Falco alerts for: `Sensitive File Read in Container`.
3. Clean up:
```bash
kubectl delete pod test-shadow-read
```
