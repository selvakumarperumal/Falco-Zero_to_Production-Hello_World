# Drop All Capabilities

| Property | Value |
|---|---|
| **Type** | Kyverno (Validation) + Falco (Detection) |
| **Kyverno Prevention** | Ensures `ALL` is listed in the dropped capabilities array of container definitions. |
| **Falco Detection** | Monitors syscalls indicating dangerous capability manipulation. |

## Description
Enforces the best practice of dropping all default Linux capabilities on containers. Detects usage of tools interacting with namespaces/capabilities (e.g. `unshare`, `nsenter`, `capsh`) at runtime.

## How to Test
### Kyverno (Admission Check)
Try to deploy a pod without specifying dropped capabilities (should be blocked):
```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-capabilities
spec:
  containers:
  - name: nginx
    image: nginx
EOF
```

### Falco (Runtime Check)
1. Run a shell and invoke a namespace manipulation utility:
```bash
kubectl run test-cap-use --image=alpine --restart=Never -it -- unshare -h
```
2. Verify Falco triggers alert: `Dangerous Capability Used at Runtime`.
3. Clean up:
```bash
kubectl delete pod test-cap-use
```
