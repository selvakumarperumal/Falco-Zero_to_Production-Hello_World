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

### CEL Expression Breakdown
```
object.status.phase == 'Failed'
```
- `object.status.phase` — Kubernetes Pod phase field (values: `Pending`, `Running`, `Succeeded`, `Failed`, `Unknown`).
- Simple equality check: deletes only pods that have definitively failed.

### Cron Schedule
`0 */6 * * *` — Runs at minute 0 of every 6th hour (00:00, 06:00, 12:00, 18:00 UTC).

---

## How to Test

### Create a Pod That Will Fail
```bash
kubectl run test-fail --image=busybox --restart=Never -- /bin/false
```

### Verify Pod is in Failed State
```bash
kubectl get pod test-fail -o jsonpath='{.status.phase}'
# Output: Failed
```

Wait for the next cron cycle to verify automatic deletion.
