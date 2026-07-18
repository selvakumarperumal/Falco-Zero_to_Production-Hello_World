# Require Resource Limits

| Property | Value |
|---|---|
| **Type** | Kyverno (Validation) + Falco (Detection) |
| **Kyverno Prevention** | Ensures CPU and Memory values are defined under resources/limits. |
| **Falco Detection** | Alerts when resource benchmarking tools like `stress`, `stress-ng`, or `yes` are spawned. |

## Description
Enforces defined resource quotas (CPU/Memory) on containers to prevent noisy-neighbor scenarios. Detects execution of benchmarking/abuse tools at runtime.

## How to Test
### Kyverno (Admission Check)
Try to create a pod without specifying resource limits (should be blocked):
```bash
kubectl run test-no-limits --image=nginx --restart=Never
```

### Falco (Runtime Check)
1. Launch a container executing the `yes` tool:
```bash
kubectl run test-exhaustion --image=alpine --restart=Never -it -- yes > /dev/null
```
2. Verify Falco logs warning alert: `Container Resource Exhaustion Behavior`.
3. Clean up:
```bash
kubectl delete pod test-exhaustion
```
