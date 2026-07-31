# Require Pod Probes

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Ensures container spec includes `livenessProbe` and `readinessProbe` blocks. |
| **Falco Detection** | Detects rapid process restarts inside containers exiting within short durations. |

## Description
Enforces configuration of liveness and readiness health probes for app reliability. Detects crash loops (rapid container restarts with exit code) at runtime.

### 🛡️ Problem Statement — What Are We Preventing?

Without health probes, Kubernetes has no visibility into whether an application inside a container is actually functioning correctly. A container can be "Running" from Kubernetes' perspective while the application inside has crashed, deadlocked, or become unresponsive:

* **Zombie Processes and Silent Failures**: A Java application may throw an `OutOfMemoryError` and stop processing requests, but the JVM process continues running. Without a `livenessProbe`, Kubernetes considers the pod healthy and never restarts it — the application is effectively dead but Kubernetes doesn't know.
* **Traffic Black Holes**: Without a `readinessProbe`, Kubernetes immediately adds a pod to the Service's endpoint list as soon as it starts, even if the application hasn't finished initialization (loading caches, establishing database connections, warming up). Incoming requests hit the pod before it's ready, resulting in errors and degraded user experience.
* **Cascading Outages**: When a pod without readiness probes fails silently, the load balancer continues routing traffic to it. As error rates increase, retry storms from clients overwhelm remaining healthy pods, creating a cascade that can take down the entire service.
* **Undetected Memory Leaks**: Applications with slow memory leaks gradually degrade over hours or days. Without liveness probes that check application health (not just process existence), these pods are never restarted, leading to progressive performance degradation.
* **Deployment Rollout Blindness**: Without readiness probes, Kubernetes rolling updates cannot distinguish between a pod that's still starting up and one that's failed to start. This can result in all pods being replaced simultaneously, causing a complete outage during deployments.

**Kyverno prevents this** by validating that every container in a pod spec defines both `livenessProbe` and `readinessProbe`, ensuring Kubernetes can detect unhealthy pods, remove them from traffic rotation, and restart them automatically. **Falco detects** rapid container crash loops at runtime, alerting on applications that may be bypassing or misconfiguring health checks.


## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: require-pod-probes
  annotations:
    policies.kyverno.io/title: Require Pod Probes
    policies.kyverno.io/category: Best Practices
    policies.kyverno.io/severity: medium
    policies.kyverno.io/description: >-
      All containers must define liveness and readiness probes to ensure
      Kubernetes can detect and recover from unhealthy states.
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
    - message: "Liveness and readiness probes are required for all containers."
      expression: >-
        object.spec.containers.all(c, has(c.livenessProbe) && has(c.readinessProbe))
```

## Falco Rule Manifest
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-custom-rules
  namespace: falco
  labels:
    app.kubernetes.io/part-of: falco
    app.kubernetes.io/component: custom-rules
data:
  falco-kyverno-rules.yaml: |-
    - rule: Container Process Crash Loop Detected
      desc: >
        Detects repeated process crashes in a container, which may
        indicate an unhealthy application bypassing health probe checks.
      source: syscall
      condition: >
        evt.type in (execve, execveat) and evt.failed = false and container
        and proc.name in (sh, bash)
        and proc.cmdline contains "exit"
        and proc.duration <= 5000000000
      output: >
        Rapid process restart detected (command=%proc.cmdline
        pod=%k8s.pod.name ns=%k8s.ns.name)
      priority: NOTICE
      tags: [kyverno_companion, health, reliability]
```

## Detailed Explanation
#### Truth Table — Kyverno CEL Evaluation

| `has(c.livenessProbe)` | `has(c.readinessProbe)` | `has(...) && has(...)` | Policy Decision |
|---|---|---|---|
| `false` | `false` | `false` | **FAIL** |
| `true` | `false` | `false` | **FAIL** |
| `false` | `true` | `false` | **FAIL** |
| `true` | `true` | `true` | **PASS** |

#### Truth Table — Falco Runtime Detections

| `container` | Process Name | Command Line | Duration | Falco Alert Result |
|---|---|---|---|
| `true` | `sh` / `bash` | `"exit 1"` | `<= 5s` | **ALERT FIRED (WARNING)** |



### Kyverno CEL Expression Breakdown

```
object.spec.containers.all(c, has(c.livenessProbe) && has(c.readinessProbe))
```

| CEL Fragment | What It Does | Why It's Needed |
|---|---|---|
| `object.spec.containers.all(c, ...)` | CEL list macro: every container must satisfy the predicate. | All containers should have health probes — one container without probes can become a "zombie" that keeps receiving traffic while hung. |
| `has(c.livenessProbe)` | Checks if the `livenessProbe` field exists on the container. | The liveness probe tells Kubernetes to restart the container if it becomes unresponsive. Without it, a deadlocked container runs forever. |
| `has(c.readinessProbe)` | Checks if the `readinessProbe` field exists on the container. | The readiness probe tells Kubernetes whether the container is ready to receive traffic. Without it, traffic is sent to containers still initializing or in a degraded state. |
| `&&` (AND) | Both probes must be present. | Liveness alone restarts unhealthy containers but doesn't prevent traffic to degraded ones. Readiness alone removes traffic but doesn't restart hung containers. Both are needed for complete health management. |

> **Note:** This policy uses `validationActions: [Audit]` because some legitimate workloads (Jobs, CronJobs, one-shot init containers) don't need probes. Start in Audit mode, identify violations, and add exceptions for batch workloads before switching to `Deny`.

> **What the policy does NOT validate:** It only checks that probes *exist* — it doesn't validate the probe configuration (type, path, port, intervals). A container with an empty `livenessProbe: {}` would pass but Kubernetes would reject it at the API level for missing required fields.

#### CEL Evaluation Trace — Container with Both Probes

```
Step 1: has(c.livenessProbe) → true (HTTP GET /healthz configured)
Step 2: has(c.readinessProbe) → true (TCP port 8080 configured)
Step 3: true && true = true → container passes
Step 4: .all() returns true → ADMITTED
```

---

### Falco Condition Breakdown

```
evt.type in (execve, execveat) and evt.failed = false and container
and proc.name in (sh, bash)
and proc.cmdline contains "exit"
and proc.duration <= 5000000000
```

| Falco Field | What It Does | Why It's Included |
|---|---|---|
| `evt.type in (execve, execveat)` | Matches process execution syscalls. | Standard process start detection. |
| `evt.failed = false` | Only successful executions. | Filters out failed attempts. |
| `container` | Event must originate inside a container. | Scopes to containerized workloads. |
| `proc.name in (sh, bash)` | Matches shell process execution. | Shell scripts wrapping an application are common entrypoints. When they exit rapidly, it suggests the application is crashing. |
| `proc.cmdline contains "exit"` | Checks if the command line includes an `exit` command. | Rapid shell exits indicate either explicit `exit` calls or crash handlers that terminate quickly. |
| `proc.duration <= 5000000000` | Process lasted less than 5 seconds (5 billion nanoseconds). | A process that starts and exits within 5 seconds is likely crashing. Normal application processes run for minutes or hours. This short duration combined with shell execution strongly suggests a crash loop. |

---

### 🔗 Defense-in-Depth: How Kyverno and Falco Work Together

| Layer | When It Acts | What It Catches |
|---|---|---|
| **Kyverno** (Admission) | At pod creation/update | Blocks pods without health probes — ensures Kubernetes can detect and recover from unhealthy containers. |
| **Falco** (Runtime) | When crash loop patterns are detected | Detects containers that are repeatedly crashing and restarting, which may indicate probes are misconfigured or the application is fundamentally broken. |

**Key gap Falco covers:** Kyverno ensures probes exist but cannot verify they are *effective*. A container could have a liveness probe that always returns 200 OK (hardcoded) while the application is actually hung. Falco detects the observable consequence — rapid process crashes — regardless of probe configuration.

### MITRE ATT&CK Mapping

| Tag | Technique | Description |
|---|---|---|
| `health` / `reliability` | **Operational Reliability** | While not a direct attack technique, containers without health probes are more susceptible to denial-of-service because Kubernetes cannot automatically detect and recover from failures. |

## Test Scenarios & Manifest Examples

### 1. ✅ PASS Case — Both `livenessProbe` and `readinessProbe` Defined
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-probes
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      livenessProbe:
        httpGet:
          path: /healthz
          port: 80
        initialDelaySeconds: 5
      readinessProbe:
        httpGet:
          path: /ready
          port: 80
        initialDelaySeconds: 2
```
* **Result**: **PASS** — Both `has(c.livenessProbe)` and `has(c.readinessProbe)` evaluate `true`.

---

### 2. ❌ FAIL Case 1 — Pod Missing `readinessProbe`
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-liveness-only
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      livenessProbe:
        httpGet:
          path: /healthz
          port: 80
```
* **Result**: **FAIL** — `has(c.readinessProbe)` evaluates `false`.

---

### 3. ❌ FAIL Case 2 — Pod Missing Probes Entirely
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-no-probes
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
```
* **Result**: **FAIL** — Lacks both probes.

---

## How to Test

### Kyverno (Admission Control Dry-Run Check)
```bash
# 1. Test PASS case (both probes specified)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-probes
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      livenessProbe:
        httpGet:
          path: /
          port: 80
      readinessProbe:
        httpGet:
          path: /
          port: 80
EOF

# 2. Test FAIL case (probes omitted)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-no-probes
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
EOF
```

### Falco (Runtime Check)
1. Run a container that exits/crashes immediately:
```bash
kubectl run test-crashing --image=alpine --restart=Never -- sh -c "exit 1"
```
2. Verify Falco triggers alert: `Container Process Crash Loop Detected`.
3. Clean up:
```bash
kubectl delete pod test-crashing --ignore-not-found
```

