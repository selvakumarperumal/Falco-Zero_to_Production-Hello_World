# Reverse Shell Detected in Container

| Property | Value |
|---|---|
| **Type** | Falco (Detection Only) |
| **Kyverno Prevention** | N/A (Runtime action). |
| **Falco Detection** | Identifies shell redirections or scripting sockets attempting outbound terminal control. |

## Description
Detects processes commonly used to spawn reverse shell connections (e.g. netcat redirects, socket creation in Python, Perl, Ruby, PHP).

## How to Test
1. Run a container and execute a netcat command structure:
```bash
kubectl run test-rev-shell --image=alpine --restart=Never -it -- nc -h
```
2. Verify Falco triggers a critical alert: `Possible Reverse Shell Detected`.
3. Clean up:
```bash
kubectl delete pod test-rev-shell
```
