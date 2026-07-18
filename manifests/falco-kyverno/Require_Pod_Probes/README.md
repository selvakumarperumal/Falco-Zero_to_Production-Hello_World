# Require Pod Probes

| Property | Value |
|---|---|
| **Type** | Kyverno (Validation) + Falco (Detection) |
| **Kyverno Prevention** | Ensures container spec includes `livenessProbe` and `readinessProbe` blocks. |
| **Falco Detection** | Detects rapid process restarts inside containers exiting within short durations. |

## Description
Enforces configuration of liveness and readiness health probes for app reliability. Detects crash loops (rapid container restarts with exit code) at runtime.

## How to Test
### Kyverno (Admission Check)
Try to deploy a pod without defining health probes (depending on mode, it registers an audit report or gets blocked):
```bash
kubectl run test-no-probes --image=nginx --restart=Never
```

### Falco (Runtime Check)
1. Run a container that exits/crashes immediately:
```bash
kubectl run test-crashing --image=alpine --restart=Never -- sh -c "exit 1"
```
2. Verify Falco triggers alert: `Container Process Crash Loop Detected`.
3. Clean up:
```bash
kubectl delete pod test-crashing
```
