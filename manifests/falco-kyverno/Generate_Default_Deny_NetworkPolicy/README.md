# Generate Default Deny NetworkPolicy

| Property | Value |
|---|---|
| **Type** | Kyverno (Generation) + Falco (Detection) |
| **Kyverno Prevention** | Generates a default-deny ingress/egress NetworkPolicy upon new namespace creation. |
| **Falco Detection** | Alerts on outbound network traffic targeting public IP addresses (ignoring internal pod/node subnets). |

## Description
Automatically generates a default-deny NetworkPolicy for any newly created namespace to ensure zero-trust segmentation. Detects unexpected outbound connections outside internal cluster network ranges at runtime.

## How to Test
### Kyverno (Admission Check)
1. Create a namespace:
```bash
kubectl create namespace test-deny-policy
```
2. Check that the NetworkPolicy is automatically created:
```bash
kubectl get netpol -n test-deny-policy
```
3. Clean up:
```bash
kubectl delete namespace test-deny-policy
```

### Falco (Runtime Check)
1. Spin up a container and ping an external server (e.g. 8.8.8.8):
```bash
kubectl run test-outbound-ping --image=alpine --restart=Never -it -- ping -c 1 8.8.8.8
```
2. Check Falco alerts for: `Unexpected Outbound Connection from Container`.
3. Clean up:
```bash
kubectl delete pod test-outbound-ping
```
