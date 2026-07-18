# Log File Deletion in Container

| Property | Value |
|---|---|
| **Type** | Falco (Detection Only) |
| **Kyverno Prevention** | N/A (Runtime file manipulation check). |
| **Falco Detection** | Monitors file-related syscalls like `unlink`, `unlinkat`, `rename`, `renameat` matching paths to log signatures. |

## Description
Detects deletion or renaming of log files (`/var/log/*`, `*.log`, `syslog`, `history`) inside a container, indicating attempts to cover tracks or delete audit records.

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
