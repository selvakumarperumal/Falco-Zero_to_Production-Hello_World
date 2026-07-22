# Cleanup Failed Pods

| Property | Value |
|---|---|
| **Type** | Kyverno (DeletingPolicy) |
| **Kyverno Action** | Cron-scheduled automatic deletion of pods in `Failed` phase every 6 hours. |
| **Falco Detection** | N/A — this is a cluster hygiene policy. |

## Description
Pods that enter the `Failed` phase (e.g. OOMKilled, ImagePullBackOff that exhausted retries, or evicted pods) remain in the cluster indefinitely unless explicitly deleted. This `DeletingPolicy` runs every 6 hours (`0 */6 * * *`) and removes any pod with `status.phase == 'Failed'`.

> **Policy Type: `DeletingPolicy`** — Runs as a cron-scheduled background job, not an admission webhook.

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
