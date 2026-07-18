# Require Standard Labels

| Property | Value |
|---|---|
| **Type** | Kyverno (Validation) |
| **Kyverno Prevention** | Validates the presence of keys matching `app.kubernetes.io/name` inside the pod metadata labels block. |
| **Falco Detection** | N/A (Metadata compliance control). |

## Description
Enforces organizational metadata compliance by validating that all submitted pods specify the `app.kubernetes.io/name` label.

## How to Test
1. Deploy a pod lacking the standard label (this triggers a warning/audit log from Kyverno):
```bash
kubectl run test-no-label --image=nginx --restart=Never
```
2. Review audit warnings or namespace PolicyReports to verify the policy violation is recorded.
3. Clean up:
```bash
kubectl delete pod test-no-label
```
