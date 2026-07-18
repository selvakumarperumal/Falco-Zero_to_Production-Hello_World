# Symlink Created to Sensitive Path

| Property | Value |
|---|---|
| **Type** | Falco (Detection Only) |
| **Kyverno Prevention** | N/A (Runtime action). |
| **Falco Detection** | Monitors symlink syscalls aiming at system path patterns. |

## Description
Detects creation of symlinks pointing to host or container-sensitive paths (`/etc/`, `/proc/`, `/sys/`, `/var/run/`). Useful for capturing symlink-based path traversal exploits (e.g. CVE-2021-25741).

## How to Test
1. Run a temporary container and generate a symlink pointing to `/etc/`:
```bash
kubectl run test-symlink-creation --image=alpine --restart=Never -it -- ln -s /etc/ /tmp/test-etc
```
2. Verify Falco triggers critical alert: `Symlink Created to Sensitive Path`.
3. Clean up:
```bash
kubectl delete pod test-symlink-creation
```
