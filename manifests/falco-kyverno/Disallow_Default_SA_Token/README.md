# Disallow Default Service Account Token

| Property | Value |
|---|---|
| **Type** | Kyverno (Validation) + Falco (Detection) |
| **Kyverno Prevention** | Validates that pods using the default service account explicitly turn off token automounting. |
| **Falco Detection** | Detects open/read syscalls targeting files under `/var/run/secrets/kubernetes.io/serviceaccount` by non-system processes. |

## Description
Enforces setting `automountServiceAccountToken: false` on pods utilizing the `default` service account to prevent default service account token mounting. Simultaneously detects runtime access to service account token files.

## How to Test
### Kyverno (Admission Check)
Try to deploy a pod with the default service account without setting `automountServiceAccountToken: false`:
```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-default-sa
spec:
  containers:
  - name: nginx
    image: nginx
EOF
```
Kyverno will validate this request (depending on the mode, it will either block the pod or report a violation in the Audit PolicyReport).

### Falco (Runtime Check)
1. Run a container and read the mounted service account token file:
```bash
kubectl run test-sa-read --image=alpine --restart=Never -it -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```
2. Verify that Falco has raised a warning alert: `Service Account Token Accessed in Container`.
3. Clean up:
```bash
kubectl delete pod test-sa-read
```
