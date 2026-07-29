# Require Standard Labels

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) |
| **Kyverno Prevention** | Validates the presence of keys matching `app.kubernetes.io/name` inside the pod metadata labels block. |
| **Falco Detection** | N/A (Metadata compliance control). |

## Description
Enforces organizational metadata compliance by validating that all submitted pods specify the `app.kubernetes.io/name` label.

### 🛡️ Problem Statement — What Are We Preventing?

Kubernetes labels are the primary mechanism for identifying, selecting, grouping, and querying resources across the cluster. Without mandatory standardized labels, clusters devolve into operational chaos:

* **Unknown Ownership**: When a pod lacks `app.kubernetes.io/name`, it becomes impossible to determine which application or team owns it. During incidents, operators cannot quickly identify the responsible team to escalate to, increasing mean-time-to-resolution (MTTR).
* **Monitoring and Alerting Gaps**: Observability tools (Prometheus, Grafana, Datadog) use labels to group metrics, create dashboards, and route alerts. Pods without standardized labels produce "orphan metrics" that don't appear in team dashboards and generate unroutable alerts.
* **Service Mesh Blind Spots**: Service mesh tools (Istio, Linkerd) rely on labels for traffic management, mTLS identity, and observability. Unlabeled pods cannot be included in mesh policies, creating security and visibility gaps.
* **Cost Attribution Failure**: Cloud cost management tools (Kubecost, CloudHealth) use Kubernetes labels to attribute compute costs to teams, projects, or environments. Unlabeled pods represent unattributed spend — a growing blind spot in cloud billing.
* **Network Policy Gaps**: Kubernetes NetworkPolicies use label selectors to define allowed communication paths. Pods without the expected labels may be excluded from security policies, either gaining too much or too little network access.

**Kyverno prevents this** by validating that every pod includes the `app.kubernetes.io/name` label with a non-empty value, ensuring all workloads are identifiable, attributable, and consistently manageable across the entire cluster lifecycle.


## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
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
  validationActions:
    - Audit
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: [CREATE, UPDATE]
        resources: [pods]
  validations:
    - message: "The label 'app.kubernetes.io/name' is required."
      expression: >-
        has(object.metadata.labels) && 'app.kubernetes.io/name' in object.metadata.labels && object.metadata.labels['app.kubernetes.io/name'] != ''
```

## Detailed Explanation
### Kyverno Policy Manifest Explanation
The validation enforces standard labelling requirements:
- **`validationActions`**: Set to `Deny` to block non-compliant requests at admission time.
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
