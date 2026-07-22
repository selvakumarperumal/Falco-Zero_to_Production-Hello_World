# Cleanup Completed Jobs

| Property | Value |
|---|---|
| **Type** | Kyverno (DeletingPolicy) |
| **Kyverno Action** | Cron-scheduled automatic deletion of completed Kubernetes Jobs daily at 2 AM UTC. |
| **Falco Detection** | N/A — this is a cluster hygiene policy, not a security rule. |

## Description
Completed Jobs accumulate in the cluster over time, consuming etcd storage and cluttering `kubectl get jobs` output. This `DeletingPolicy` runs on a cron schedule (`0 2 * * *`) and evaluates CEL conditions against all matching Jobs. If a Job has a `Complete` status condition, it is automatically deleted.

> **Policy Type: `DeletingPolicy`** — This is NOT an admission webhook. It runs as a background cron job managed by the Kyverno cleanup controller, independently of resource creation/update events.

---

## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: DeletingPolicy
metadata:
  name: cleanup-completed-jobs
  annotations:
    policies.kyverno.io/title: Cleanup Completed Jobs
    policies.kyverno.io/category: Cluster Hygiene
    policies.kyverno.io/severity: low
    policies.kyverno.io/description: >-
      Automatically deletes completed Kubernetes Jobs daily at 2 AM UTC
      to prevent stale resources from accumulating in the cluster.
  labels:
    app.kubernetes.io/part-of: kyverno-falco-policies
spec:
  schedule: '0 2 * * *'
  matchConstraints:
    resourceRules:
      - apiGroups: ['batch']
        apiVersions: ['v1']
        resources: ['jobs']
  conditions:
    - name: is-completed
      expression: >-
        object.status.conditions.exists(c,
          c.type == 'Complete' && c.status == 'True')
```

---

## Detailed Explanation

### Key Fields
| Field | Purpose |
|---|---|
| `schedule` | Standard cron expression (`0 2 * * *` = daily at 2 AM UTC). Minimum granularity: 1 minute. |
| `matchConstraints.resourceRules` | Targets `batch/v1 Jobs` across all namespaces. |
| `conditions` | CEL expressions evaluated per matched resource. All must return `true` for deletion. |

### CEL Expression Breakdown
```
object.status.conditions.exists(c, c.type == 'Complete' && c.status == 'True')
```
- `object.status.conditions` — Kubernetes Job status conditions list.
- `.exists(c, ...)` — CEL macro: returns `true` if at least one element satisfies the predicate.
- `c.type == 'Complete' && c.status == 'True'` — Matches the standard Kubernetes Job completion condition.

### RBAC Requirements
The Kyverno cleanup controller requires permissions to delete Jobs:
```yaml
rules:
  - apiGroups: ['batch']
    resources: ['jobs']
    verbs: ['get', 'list', 'watch', 'delete']
```

---

## How to Test

### Verify the Policy is Active
```bash
kubectl get deletingpolicies
```

### Create a Test Job
```bash
kubectl create job test-cleanup --image=busybox -- echo "done"
```

Wait for the job to complete, then wait for the next cron cycle (or manually trigger) to verify deletion.
