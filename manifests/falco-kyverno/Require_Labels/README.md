# Require Standard Labels

| Property | Value |
|---|---|
| **Type** | Kyverno (Validation) |
| **Kyverno Prevention** | Validates the presence of keys matching `app.kubernetes.io/name` inside the pod metadata labels block. |
| **Falco Detection** | N/A (Metadata compliance control). |

## Description
Enforces organizational metadata compliance by validating that all submitted pods specify the `app.kubernetes.io/name` label.

## Kyverno Policy Manifest
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-labels
  annotations:
    policies.kyverno.io/title: Require Standard Labels
    policies.kyverno.io/category: Best Practices
    policies.kyverno.io/severity: low
    policies.kyverno.io/description: >-
      All Pods must have the app.kubernetes.io/name label.
  labels:
    app.kubernetes.io/part-of: kyverno-falco-policies
spec:
  validationFailureAction: Audit
  rules:
    - name: require-app-label
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: "The label 'app.kubernetes.io/name' is required."
        pattern:
          metadata:
            labels:
              app.kubernetes.io/name: "?*"
```

## Detailed Explanation
### Kyverno Policy Manifest Explanation
The validation enforces standard labelling requirements:
- **`validationFailureAction: Audit`**: Allows non-compliant pods to boot, but flags them in `PolicyReport` for compliance scanning.
- **`validate.pattern.metadata.labels`**:
  - `app.kubernetes.io/name: "?*"`: Evaluates labels. The `?*` pattern means the label must be present and contain at least one character.

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
