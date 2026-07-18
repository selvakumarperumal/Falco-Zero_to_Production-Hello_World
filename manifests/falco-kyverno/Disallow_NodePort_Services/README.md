# Disallow NodePort Services

| Property | Value |
|---|---|
| **Type** | Kyverno (Validation) + Falco (Detection) |
| **Kyverno Prevention** | Enforces that service definitions do not specify `type: NodePort`. |
| **Falco Detection** | Monitors `bind`/`listen` syscalls to detect processes binding to unexpected ports (excluding ports like 80, 443, 8080, etc.). |

## Description
Blocks Services using `type: NodePort` which bypasses Ingress/LoadBalancers and exposes host-level ports. Detects containers binding to unexpected non-standard listening ports at runtime.

## How to Test
### Kyverno (Admission Check)
Try to deploy a service using NodePort (should be blocked):
```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: test-nodeport
spec:
  type: NodePort
  ports:
  - port: 80
  selector:
    app: nginx
EOF
```

### Falco (Runtime Check)
1. Run a container and listen on an unapproved port:
```bash
kubectl run test-port-bind --image=alpine --restart=Never -it -- nc -l -p 9999
```
2. Verify Falco alerts show: `Unexpected Listening Port in Container`.
