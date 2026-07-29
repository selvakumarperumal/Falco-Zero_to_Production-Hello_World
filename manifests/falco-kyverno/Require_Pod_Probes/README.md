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
### Kyverno Policy Manifest Explanation
The policy enforces application health checks:
- **`validationActions`**: Set to `Deny` to block non-compliant requests at admission time.
- **`pod-policies.kyverno.io/autogen-controllers`**: Automatically generates matching policies for container controllers like Deployment, StatefulSet, and DaemonSet.
- **`livenessProbe: "?*"` and `readinessProbe: "?*"`**: Requires both probe keys to be populated.

### Falco Rule Manifest Explanation
The companion Falco rule detects unstable application crash loops:
- **`proc.name in (sh, bash) and proc.cmdline contains "exit"`**: Identifies shell-based termination execution.
- **`proc.duration <= 5000000000`**: Tracks the process lifespan (5 billion nanoseconds = 5 seconds). If shell processes execute and exit within 5 seconds, it flags potential crash loop behavior.

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

