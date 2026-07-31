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
#### Truth Table — Kyverno Cleanup Evaluation

| `has(status.succeeded)` | `status.succeeded` Value | `status.succeeded > 0` | Policy Action |
|---|---|---|---|
| `false` | — | `false` | Retain Job (Not completed) |
| `true` | `0` | `false` | Retain Job (In progress or failed) |
| `true` | `>= 1` | `true` | **CLEANUP / DELETE JOB** (Job succeeded) |



### Kyverno CEL DeletingPolicy Breakdown

```yaml
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

| Field / CEL Fragment | What It Does | Why It's Needed |
|---|---|---|
| `kind: DeletingPolicy` | Kyverno policy type for background resource cleanup. | Unlike admission webhooks, DeletingPolicy runs as a background cron controller. |
| `schedule: '0 2 * * *'` | Cron schedule expression (daily at 02:00 UTC). | Controls how frequently Kyverno checks for stale resources to delete. |
| `object.status.conditions` | Accesses the array of status condition objects on the Job. | Job completion state is tracked in the status condition list. |
| `.exists(c, ...)` | CEL list macro: returns `true` if any element matches. | Scans condition objects for the completion marker. |
| `c.type == 'Complete' && c.status == 'True'` | Evaluates if condition type is `Complete` and status is `True`. | Identifies successfully finished Jobs while preserving failed or active Jobs. |

---

### ℹ️ Why There Is No Falco Companion Rule

Resource deletion for cluster hygiene is an administrative background cleanup task managed by Kyverno's cleanup controller.

* **Cluster Hygiene**: Deleting stale Job etcd objects does not correspond to a security threat or runtime attack vector.
* **No Runtime Syscall**: No Linux kernel syscalls occur during etcd object garbage collection.

---

---

## Test Scenarios & Manifest Examples

### 1. ✅ TARGET FOR DELETION — Completed Job
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: test-completed-job
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: task
          image: busybox:1.36
          command: ["echo", "job finished successfully"]
      restartPolicy: Never
```
* **Result**: **DELETED** — Upon job completion, `object.status.conditions` contains `{type: "Complete", status: "True"}`. The CEL condition evaluates to `true` on the cron schedule (`0 2 * * *`), deleting the resource.

---

### 2. 🛡️ IGNORED FROM DELETION — Failed Job
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: test-failed-job
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: task
          image: busybox:1.36
          command: ["sh", "-c", "exit 1"]
      restartPolicy: Never
```
* **Result**: **NOT DELETED** — When a job fails, `object.status.conditions` contains `{type: "Failed", status: "True"}`. The CEL condition `c.type == 'Complete'` evaluates to `false`, leaving the failed job intact for investigation.

---

## How to Test

### Verify DeletingPolicy Configuration
```bash
# Verify the policy is installed and inspect its schedule
kubectl get deletingpolicies cleanup-completed-jobs -o yaml
```

### Create Completed & Failed Test Jobs
```bash
# 1. Create a job that will succeed (target for cleanup)
kubectl create job test-job-pass --image=busybox:1.36 -- echo "success"

# 2. Create a job that will fail (should be preserved)
kubectl create job test-job-fail --image=busybox:1.36 -- sh -c "exit 1"

# 3. Check status conditions after execution
kubectl get job test-job-pass test-job-fail -o custom-columns=NAME:.metadata.name,CONDITIONS:.status.conditions[*].type
```
*Expected conditions output:* `Complete` for `test-job-pass` and `Failed` for `test-job-fail`.

