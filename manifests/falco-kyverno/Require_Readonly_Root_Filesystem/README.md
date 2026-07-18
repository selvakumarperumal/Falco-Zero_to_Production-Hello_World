# Require Read-Only Root Filesystem

| Property | Value |
|---|---|
| **Type** | Kyverno (Validation) + Falco (Detection) |
| **Kyverno Prevention** | Validates `readOnlyRootFilesystem: true` under container securityContext. |
| **Falco Detection** | Tracks open/write syscalls targeting root directories (excluding exceptions like `/tmp`). |

## Description
Enforces setting the root filesystem as read-only, restricting writable storage to ephemeral/persistent volumes. Detects write attempts to unauthorized root directory structures.

## How to Test
### Kyverno (Admission Check)
Create a pod without setting readOnlyRootFilesystem to true (triggers Audit or Enforce):
```bash
kubectl run test-writable-fs --image=nginx --restart=Never
```

### Falco (Runtime Check)
1. Run a pod and try to write directly to a root directory:
```bash
kubectl run test-root-write --image=alpine --restart=Never -it -- sh -c "echo 'bad' > /root/compromised.txt"
```
2. Check Falco alerts for: `Write to Container Root Filesystem`.
3. Clean up:
```bash
kubectl delete pod test-root-write
```
