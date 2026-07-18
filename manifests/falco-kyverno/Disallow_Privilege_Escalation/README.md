# Disallow Privilege Escalation

| Property | Value |
|---|---|
| **Type** | Kyverno (Validation) + Falco (Detection) |
| **Kyverno Prevention** | Enforces `allowPrivilegeEscalation: false` on all containers. |
| **Falco Detection** | Detects spawned processes of setuid/setgid binaries like `sudo`, `su`, `passwd` at runtime. |

## Description
Ensures that `allowPrivilegeEscalation` is configured as false (preventing sub-processes from gaining more privileges than their parent). Detects execution of setuid/setgid binaries inside containers.

## How to Test
### Kyverno (Admission Check)
Deploy a pod explicitly enabling privilege escalation (should be blocked):
```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-priv-esc
spec:
  containers:
  - name: nginx
    image: nginx
    securityContext:
      allowPrivilegeEscalation: true
EOF
```

### Falco (Runtime Check)
1. Run a container and try executing a setuid/setgid binary such as `su`:
```bash
kubectl run test-su --image=alpine --restart=Never -it -- su
```
2. Check Falco alerts for: `Setuid or Setgid Binary Executed in Container`.
3. Clean up:
```bash
kubectl delete pod test-su
```
