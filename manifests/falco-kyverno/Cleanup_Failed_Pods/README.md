# Cleanup Failed Pods

| Property | Value |
|---|---|
| **Type** | Kyverno (DeletingPolicy) |
| **Kyverno Action** | Cron-scheduled automatic deletion of pods in `Failed` phase every 6 hours. |
| **Falco Detection** | N/A — this is a cluster hygiene policy. |

## Description
Pods that enter the `Failed` phase (e.g. OOMKilled, ImagePullBackOff that exhausted retries, or evicted pods) remain in the cluster indefinitely unless explicitly deleted. This `DeletingPolicy` runs every 6 hours (`0 */6 * * *`) and removes any pod with `status.phase == 'Failed'`.

### 🛡️ Problem Statement — What Are We Preventing?

Kubernetes does not automatically remove pods in the `Failed` phase. These zombie pods persist indefinitely, creating operational, security, and resource issues:

* **Resource Waste**: Failed pods retain their resource reservations (CPU/memory requests) on the node even though they perform no useful work. In clusters with tight capacity, this phantom resource consumption can prevent healthy pods from being scheduled.
* **Misleading Monitoring Signals**: Monitoring dashboards and alerting systems (Prometheus, Datadog, etc.) that track pod counts or failure rates produce inaccurate signals when stale failed pods inflate the failure metrics. Teams waste time investigating stale failures instead of focusing on active incidents.
* **Security Information Leakage**: Failed pods may contain environment variables, mounted secrets, or configuration data in their spec. Leaving them in the cluster extends the exposure window for anyone with `kubectl describe` access to read sensitive configuration.
* **Namespace Clutter**: In CI/CD-heavy clusters where pipelines spawn hundreds of ephemeral pods, failed pods accumulate rapidly and make `kubectl get pods` output unmanageable, slowing operational debugging.
* **ResourceQuota Exhaustion**: Failed pods count against namespace-level ResourceQuota object counts, potentially blocking creation of new pods in quota-constrained namespaces.

**Kyverno prevents this** by running a `DeletingPolicy` every 6 hours that evaluates each pod's `status.phase` field and automatically removes any pod in the `Failed` state, keeping namespaces clean and resource accounting accurate.


---

## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: DeletingPolicy
metadata:
  name: cleanup-failed-pods
  annotations:
    policies.kyverno.io/title: Cleanup Failed Pods
    policies.kyverno.io/category: Cluster Hygiene
    policies.kyverno.io/severity: low
    policies.kyverno.io/description: >-
      Automatically deletes pods in Failed phase every 6 hours to prevent
      stale failed pods from consuming cluster resources and cluttering
      namespace listings.
  labels:
    app.kubernetes.io/part-of: kyverno-falco-policies
spec:
  schedule: '0 */6 * * *'
  matchConstraints:
    resourceRules:
      - apiGroups: ['']
        apiVersions: ['v1']
        resources: ['pods']
  conditions:
    - name: is-failed
      expression: "object.status.phase == 'Failed'"
```

---

## Detailed Explanation
#### Truth Table — Kyverno Cleanup Evaluation

| `has(status.phase)` | `status.phase` Value | `status.phase == 'Failed'` | Policy Action |
|---|---|---|---|
| `false` | — | `false` | Retain Pod |
| `true` | `'Running'` / `'Succeeded'` | `false` | Retain Pod |
| `true` | `'Failed'` | `true` | **CLEANUP / DELETE POD** (Pod failed) |



### Kyverno CEL DeletingPolicy Breakdown

```yaml
spec:
  schedule: '0 */6 * * *'
  matchConstraints:
    resourceRules:
      - apiGroups: ['']
        apiVersions: ['v1']
        resources: ['pods']
  conditions:
    - name: is-failed
      expression: "object.status.phase == 'Failed'"
```

| Field / CEL Fragment | What It Does | Why It's Needed |
|---|---|---|
| `kind: DeletingPolicy` | Kyverno policy type for cron-based background cleanup. | Executes periodic checks on matching cluster objects. |
| `schedule: '0 */6 * * *'` | Cron schedule expression (runs every 6 hours). | Regularly purges accumulated failed Pod objects. |
| `object.status.phase` | Reads the high-level Pod lifecycle phase field (`Pending`, `Running`, `Succeeded`, `Failed`, `Unknown`). | Identifies the lifecycle state of the pod object. |
| `object.status.phase == 'Failed'` | CEL equality comparison matching the literal string `'Failed'`. | Matches Pods in Failed phase (e.g. OOMKilled, evicted, exited with non-zero status). |

---

### ℹ️ Why There Is No Falco Companion Rule

Deleting stale Failed Pod objects is a cluster hygiene operation managed by Kyverno's cleanup controller.

* **Administrative Hygiene**: Removes dead etcd Pod objects to free up object quota and reduce noise.
* **Runtime Crash Monitoring Covered**: Monitoring runtime process crashes and exit behaviors is handled by [Require Pod Probes](../Require_Pod_Probes/README.md).

---

## Test Scenarios & Manifest Examples

### 1. ✅ TARGET FOR DELETION — Failed Pod
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-failed-pod
  namespace: default
spec:
  restartPolicy: Never
  containers:
    - name: app
      image: busybox:1.36
      command: ["/bin/false"]
```
* **Result**: **DELETED** — The container exits with exit code 1 and `restartPolicy: Never`, causing the pod phase to become `status.phase == 'Failed'`. Kyverno's cleanup controller evaluates the condition `true` and deletes the pod on schedule (`0 */6 * * *`).

---

### 2. 🛡️ IGNORED FROM DELETION — Succeeded or Running Pod
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-succeeded-pod
  namespace: default
spec:
  restartPolicy: Never
  containers:
    - name: app
      image: busybox:1.36
      command: ["echo", "finished"]
```
* **Result**: **NOT DELETED** — The pod completes with phase `Succeeded`. `object.status.phase == 'Failed'` evaluates to `false`, leaving the pod untouched by this specific policy.

---

## How to Test

### Create Test Pods
```bash
# 1. Create a pod that fails (target for deletion)
kubectl run test-fail-pod --image=busybox:1.36 --restart=Never -- /bin/false

# 2. Verify phase is 'Failed'
kubectl get pod test-fail-pod -o jsonpath='{.status.phase}'
# Output: Failed

# 3. Clean up manually if not waiting for cron schedule
kubectl delete pod test-fail-pod --ignore-not-found
```

