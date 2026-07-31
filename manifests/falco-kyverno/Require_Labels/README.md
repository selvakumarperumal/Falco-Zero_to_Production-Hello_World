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

### Kyverno CEL Expression Breakdown

```
has(object.metadata.labels) &&
'app.kubernetes.io/name' in object.metadata.labels &&
object.metadata.labels['app.kubernetes.io/name'] != ''
```

| CEL Fragment | What It Does | Why It's Needed |
|---|---|---|
| `has(object.metadata.labels)` | Checks if the `labels` map exists under `metadata`. | Prevents null pointer error if a resource is created without any labels map. |
| `'app.kubernetes.io/name' in object.metadata.labels` | Checks if the required label key `app.kubernetes.io/name` exists in the labels map. | Verifies the standard label key is present. |
| `object.metadata.labels['app.kubernetes.io/name'] != ''` | Checks that the value associated with `app.kubernetes.io/name` is non-empty. | Rejects manifests that include the key but set an empty string value (e.g. `app.kubernetes.io/name: ""`). |

---

### ℹ️ Why There Is No Falco Companion Rule

Labels are pure Kubernetes API object **metadata**. They exist solely in the Kubernetes API server / etcd database to categorize and filter resources.

* **No Syscall Representation**: There is no Linux kernel syscall or runtime process event associated with Kubernetes resource labels.
* **Admission Control Control**: Label enforcement is strictly an admission-time metadata concern handled by Kyverno during `CREATE` and `UPDATE` operations.

## Test Scenarios & Manifest Examples

### 1. ✅ PASS Case — Pod Specifying Required `app.kubernetes.io/name` Label
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-labeled-pod
  namespace: default
  labels:
    app.kubernetes.io/name: payment-service
```
* **Result**: **PASS** — `has(metadata.labels)` evaluates `true`, `'app.kubernetes.io/name' in labels` evaluates `true`, and value is non-empty.

---

### 2. ❌ FAIL Case 1 — Pod Missing `metadata.labels` Block Entirely
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-no-labels
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
```
* **Result**: **FAIL** — `has(object.metadata.labels)` evaluates `false`.

---

### 3. ❌ FAIL Case 2 — Pod Has Labels, But Missing `app.kubernetes.io/name`
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-wrong-label
  namespace: default
  labels:
    tier: frontend
spec:
  containers:
    - name: app
      image: nginx:1.25
```
* **Result**: **FAIL** — `'app.kubernetes.io/name' in object.metadata.labels` evaluates `false`.

---

### 4. ❌ FAIL Case 3 — Empty Label Value (`app.kubernetes.io/name: ""`)
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-empty-label
  namespace: default
  labels:
    app.kubernetes.io/name: ""
spec:
  containers:
    - name: app
      image: nginx:1.25
```
* **Result**: **FAIL** — `object.metadata.labels['app.kubernetes.io/name'] != ''` evaluates `false`.

---

## How to Test

### Kyverno (Admission Control Dry-Run Check)
```bash
# 1. Test PASS case (properly labeled pod)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-labeled
  namespace: default
  labels:
    app.kubernetes.io/name: my-app
spec:
  containers:
    - name: app
      image: nginx:1.25
EOF

# 2. Test FAIL case (unlabeled pod)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-unlabeled
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
EOF
```

