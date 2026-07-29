# Cleanup Completed Jobs

| Property | Value |
|---|---|
| **Type** | Kyverno (DeletingPolicy) |
| **Kyverno Action** | Cron-scheduled automatic deletion of completed Kubernetes Jobs daily at 2 AM UTC. |
| **Falco Detection** | N/A — this is a cluster hygiene policy, not a security rule. |

## Description
Completed Jobs accumulate in the cluster over time, consuming etcd storage and cluttering `kubectl get jobs` output. This `DeletingPolicy` runs on a cron schedule (`0 2 * * *`) and evaluates CEL conditions against all matching Jobs. If a Job has a `Complete` status condition, it is automatically deleted.

### 🛡️ Problem Statement — What Are We Preventing?

Kubernetes does not automatically clean up completed Jobs. Over weeks and months, thousands of stale Job objects pile up in the cluster, creating several operational and security issues:

* **etcd Storage Exhaustion**: Every completed Job object (including its pod template, status history, and metadata) persists in etcd. In clusters running frequent CronJobs or batch workloads, this can consume gigabytes of etcd storage, degrading API server performance and increasing backup times.
* **Operational Noise**: `kubectl get jobs` becomes unusable when thousands of completed Jobs clutter namespace listings, making it difficult for operators to identify currently running or failed jobs that need attention.
* **Audit Log Inflation**: Stale Jobs continue to appear in RBAC audit logs and monitoring dashboards, making security investigations and compliance audits harder by hiding meaningful events in a sea of irrelevant completed entries.
* **Resource Quota Pressure**: In namespaces with ResourceQuotas on object counts, accumulated Jobs can block creation of new Jobs, causing CronJob schedules to fail silently.
* **Incident Response Confusion**: During a production incident, operators scanning for failing workloads must mentally filter out hundreds of old completed Jobs, slowing mean-time-to-recovery (MTTR).

**Kyverno prevents this** by running a `DeletingPolicy` on a cron schedule that evaluates each Job's status and automatically removes Jobs that have completed successfully, keeping the cluster clean without any manual intervention.


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
