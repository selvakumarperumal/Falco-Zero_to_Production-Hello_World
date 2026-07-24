# Log File Deletion in Container

| Property | Value |
|---|---|
| **Type** | Falco (Detection Only) |
| **Kyverno Prevention** | N/A (Runtime file manipulation check). |
| **Falco Detection** | Monitors file-related syscalls like `unlink`, `unlinkat`, `rename`, `renameat` matching paths to log signatures. |

## Description
Detects deletion or renaming of log files (`/var/log/*`, `*.log`, `syslog`, `history`) inside a container, indicating attempts to cover tracks or delete audit records.

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
    - rule: Log File Deletion in Container
      desc: >
        Detects deletion of log files inside a container, which may
        indicate an attacker covering their tracks.
      condition: >
        evt.type in (unlink, unlinkat, rename, renameat)
        and container
        and (fd.name startswith "/var/log/"
          or fd.name endswith ".log"
          or fd.name contains "syslog"
          or fd.name contains "auth.log"
          or fd.name contains "history")
        and not proc.name in (logrotate, journald)
      output: >
        Log file deleted in container (file=%fd.name command=%proc.cmdline
        pod=%k8s.pod.name ns=%k8s.ns.name user=%user.name)
      priority: ERROR
      tags: [runtime_only, log_tampering, mitre_defense_evasion]
```

## Detailed Explanation
### Falco Rule Manifest Explanation
The rule targets defense evasion patterns inside containers:
- **`evt.type in (unlink, unlinkat, rename, renameat)`**: Listens for file deletion (`unlink`) and renaming (`rename`) syscalls.
- **`fd.name startswith "/var/log/"` or `endswith ".log"` or contains `syslog`, `auth.log`, `history`**: Focuses on files matching typical logging directories, extensions, or system log files.
- **`not proc.name in (logrotate, journald)`**: Safe lists authorized system processes that naturally truncate or archive logs.

## How to Test
1. Launch a temporary container and perform file write/delete operations inside `/var/log`:
```bash
kubectl run test-log-del --image=alpine --restart=Never -it -- sh -c "touch /var/log/test.log && rm /var/log/test.log"
```
2. Verify Falco logs an error alert: `Log File Deletion in Container`.
3. Clean up:
```bash
kubectl delete pod test-log-del
```
