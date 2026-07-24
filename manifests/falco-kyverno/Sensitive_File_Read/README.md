# Sensitive File Read in Container

| Property | Value |
|---|---|
| **Type** | Falco (Detection Only) |
| **Kyverno Prevention** | N/A (Runtime file action). |
| **Falco Detection** | Monitors open/read events on sensitive file extensions or path matching. |

## Description
Detects unauthorized access/reading of credentials, security files (`/etc/shadow`, `/etc/gshadow`, `/etc/master.passwd`), private keys (`.pem`, `.key`), or SSH keys inside a container.

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
  # -------------------------------------------------------------------------
  # Original hello-world rules (preserved from existing ConfigMap)
  # -------------------------------------------------------------------------
  hello-world-rules.yaml: |-
    - rule: Sensitive File Read in Container
      desc: >
        Detects access to sensitive credential files from inside a
        container.
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
