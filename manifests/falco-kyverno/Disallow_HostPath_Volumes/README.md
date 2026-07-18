# Disallow HostPath Volumes

| Property | Value |
|---|---|
| **Type** | Kyverno (Validation) + Falco (Detection) |
| **Kyverno Prevention** | Rejects any pod creation spec containing a `hostPath` volume definition. |
| **Falco Detection** | Detects reads/writes to sensitive paths on host filesystems. |

## Description
Blocks configuration of `hostPath` volumes which allow pods direct access to the node's filesystem. Monitors and alerts on access to sensitive paths (like `/etc/shadow`, `/var/run/docker.sock`) at runtime.

## How to Test
### Kyverno (Admission Check)
Try to create a pod mounting a host path (it should be blocked immediately):
```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-hostpath
spec:
  containers:
  - name: nginx
    image: nginx
    volumeMounts:
    - mountPath: /host
      name: host-vol
  volumes:
  - name: host-vol
    hostPath:
      path: /
EOF
```

### Falco (Runtime Check)
Verify that any access to system critical paths like `/etc/shadow` generates a critical level alert: `Sensitive Host Path Accessed from Container`.
