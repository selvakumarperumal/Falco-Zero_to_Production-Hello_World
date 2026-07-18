# Require Run As Non Root

| Property | Value |
|---|---|
| **Type** | Kyverno (Validation) + Falco (Detection) |
| **Kyverno Prevention** | Enforces `runAsNonRoot: true` in the container securityContext. |
| **Falco Detection** | Alerts when a spawned process is executed with UID 0 (root) inside namespaces. |

## Description
Ensures containers run as non-root users (UID != 0). Monitors and alerts on root UID execution at runtime.

## How to Test
### Kyverno (Admission Check)
Attempt to deploy a standard root-default container (should be blocked):
```bash
kubectl run test-root-deploy --image=nginx --restart=Never
```

### Falco (Runtime Check)
1. Spawn a shell running as root:
```bash
kubectl run test-root-check --image=alpine --restart=Never -it -- id
```
2. Verify Falco fires: `Container Running as Root User`.
3. Clean up:
```bash
kubectl delete pod test-root-check
```
