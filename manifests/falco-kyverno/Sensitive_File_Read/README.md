# Sensitive File Read in Container

| Property | Value |
|---|---|
| **Type** | Falco (Detection Only) |
| **Kyverno Prevention** | N/A (Runtime file action). |
| **Falco Detection** | Monitors open/read events on sensitive file extensions or path matching. |

## Description
Detects unauthorized access/reading of credentials, security files (`/etc/shadow`, `/etc/gshadow`, `/etc/master.passwd`), private keys (`.pem`, `.key`), or SSH keys inside a container.

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
