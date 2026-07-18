# Disallow Host Namespaces

| Property | Value |
|---|---|
| **Type** | Kyverno (Validation) + Falco (Detection) |
| **Kyverno Prevention** | Enforces `hostPID: false`, `hostIPC: false`, and `hostNetwork: false` on pod specifications. |
| **Falco Detection** | Detects container start events containing flags `CLONE_NEWPID` or `CLONE_NEWNET`. |

## Description
Blocks pods sharing host PID, IPC, or Network namespaces (which breaks node isolation). Detects namespace clone flags during container startup at runtime.

## How to Test
### Kyverno (Admission Check)
Attempt to deploy a pod with host namespace access enabled (should be blocked):
```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-host-ns
spec:
  hostPID: true
  containers:
  - name: nginx
    image: nginx
EOF
```

### Falco (Runtime Check)
If admission control is bypassed or in audit-only mode, starting a container with host namespaces will fire the alert: `Container Using Host Namespace`.
