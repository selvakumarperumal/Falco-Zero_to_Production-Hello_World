# Require Resource Limits

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Ensures CPU and Memory values are defined under resources/limits. |
| **Falco Detection** | Alerts when resource benchmarking tools like `stress`, `stress-ng`, or `yes` are spawned. |

## Description
Enforces defined resource quotas (CPU/Memory) on containers to prevent noisy-neighbor scenarios. Detects execution of benchmarking/abuse tools at runtime.

### 🛡️ Problem Statement — What Are We Preventing?

Without CPU and memory limits, a single container can consume all available resources on a node, starving co-located pods and destabilizing the entire cluster. This creates critical availability and security risks:

* **Resource Exhaustion Attacks (MITRE ATT&CK: T1499.004)**: An attacker who gains code execution inside an unlimited container can run fork bombs (`:(){ :|:& };:`), CPU stress tools (`stress-ng`), or memory allocation loops to deliberately exhaust node resources. Without limits, the Linux kernel cannot constrain the container, and the attack impacts every other pod on the node.
* **Noisy Neighbor Problem**: In multi-tenant clusters, a single team's runaway workload (memory leak, infinite loop, unoptimized query) can consume all node CPU or memory, causing latency spikes, OOM kills, and restarts for pods belonging to other teams — even though those pods are functioning correctly.
* **Node-Level OOM Kills**: Without memory limits, the Linux kernel's OOM killer selects victims based on memory consumption patterns rather than cgroup boundaries. It may kill critical system pods (`kubelet`, `kube-proxy`, `CNI agents`) instead of the offending unlimited container, causing the entire node to become unresponsive.
* **Cloud Cost Explosion**: Unlimited containers that consume excessive resources trigger cluster autoscaler scale-ups, provisioning expensive new nodes to handle artificial demand. Without limits, there's no ceiling on per-pod resource consumption, making cloud costs unpredictable.
* **Cryptocurrency Mining Enabler**: Crypto miners are specifically designed to consume 100% of available CPU. Without CPU limits, a miner deployed in an unlimited container can consume the entire node's compute capacity, maximizing the attacker's mining output at the organization's expense.

**Kyverno prevents this** by validating that every container defines explicit `resources.limits.cpu` and `resources.limits.memory` values, ensuring the Linux kernel's cgroup subsystem enforces hard boundaries on resource consumption. **Falco detects** the execution of known resource abuse tools (`stress`, `stress-ng`, `yes`, `dd`) inside containers, alerting on potential resource exhaustion attacks.


## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: require-resource-limits
  annotations:
    policies.kyverno.io/title: Require Resource Limits
    policies.kyverno.io/category: Best Practices
    policies.kyverno.io/severity: medium
    policies.kyverno.io/description: >-
      All containers must define CPU and memory limits to prevent resource
      exhaustion on shared nodes.
  labels:
    app.kubernetes.io/part-of: kyverno-falco-policies
spec:
  validationActions:
    - Deny
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: [CREATE, UPDATE]
        resources: [pods]
  validations:
    - message: "CPU and memory limits are required for all containers."
      expression: >-
        object.spec.containers.all(c,
          has(c.resources) &&
          has(c.resources.limits) &&
          has(c.resources.limits.cpu) &&
          has(c.resources.limits.memory)
        )
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
    - rule: Container Resource Exhaustion Behavior
      desc: >
        Detects a container process consuming excessive resources,
        potentially indicating a fork bomb or resource exhaustion attack.
      source: syscall
      condition: >
        evt.type in (execve, execveat) and evt.failed = false and container
        and proc.name in (stress, stress-ng, yes, dd)
        and not k8s.ns.name in (kube-system)
      output: >
        Resource exhaustion tool detected (command=%proc.cmdline
        pod=%k8s.pod.name ns=%k8s.ns.name image=%container.image.repository)
      priority: WARNING
      tags: [kyverno_companion, resource_abuse, mitre_impact]
```

## Detailed Explanation

### Kyverno CEL Expression Breakdown

```
object.spec.containers.all(c,
  has(c.resources) &&
  has(c.resources.limits) &&
  has(c.resources.limits.cpu) &&
  has(c.resources.limits.memory)
)
```

| CEL Fragment | What It Does | Why It's Needed |
|---|---|---|
| `object.spec.containers.all(c, ...)` | CEL list macro: returns `true` only if **every** container satisfies the predicate. | All containers must have resource limits — even one unlimited container can starve node resources. |
| `has(c.resources)` | Checks if the `resources` field exists on the container. | The `resources` field is optional in Kubernetes. If it's missing entirely, accessing `.limits` would cause a CEL evaluation error. |
| `has(c.resources.limits)` | Checks if the `limits` sub-field exists within `resources`. | A container can have `resources.requests` without `resources.limits` — this ensures limits are explicitly defined. |
| `has(c.resources.limits.cpu)` | Checks if a CPU limit value is specified. | Without a CPU limit, the container can consume all available CPU on the node, starving other pods. |
| `has(c.resources.limits.memory)` | Checks if a memory limit value is specified. | Without a memory limit, the container can allocate unlimited memory, triggering the Linux OOM killer which may kill other pods. |
| `&&` (AND chain) | All four `has()` checks must pass for each container. | The chain creates a progressive null-safety check: resources → limits → cpu/memory. Each `has()` guards the next field access. |

> **Note:** This policy only checks that limits **exist** — it does not validate their values. A container with `cpu: "1m"` and `memory: "1Mi"` would pass. To enforce minimum values, add a comparison like `quantity(c.resources.limits.cpu) >= quantity("100m")`.

#### CEL Evaluation Trace — Container with Both Limits

```
Step 1: has(c.resources) → true (resources field exists)
Step 2: has(c.resources.limits) → true (limits field exists)
Step 3: has(c.resources.limits.cpu) → true (cpu: "500m")
Step 4: has(c.resources.limits.memory) → true (memory: "512Mi")
Step 5: true && true && true && true = true → container passes
Step 6: .all() returns true → ADMITTED
```

#### CEL Evaluation Trace — Container with No Resources

```
Step 1: has(c.resources) → false
Step 2: false && ... → SHORT-CIRCUIT (remaining checks skipped)
Step 3: Predicate returns false → .all() returns false → DENIED
```

---

### Falco Condition Breakdown

```
evt.type in (execve, execveat) and evt.failed = false and container
and proc.name in (stress, stress-ng, yes, dd)
and not k8s.ns.name in (kube-system)
```

| Falco Field | What It Does | Why It's Included |
|---|---|---|
| `evt.type in (execve, execveat)` | Matches process execution syscalls. | Standard process start detection filter. |
| `evt.failed = false` | Only successful executions. | We only care about tools that actually started running. |
| `container` | Event originates inside a container. | Host-level stress testing tools are not relevant to this policy. |
| `proc.name in (stress, stress-ng, yes, dd)` | Matches known resource abuse tool binaries. `stress` and `stress-ng` are CPU/memory stress testers. `yes` outputs infinite data to consume CPU. `dd` can perform intensive disk I/O. | These tools have no legitimate use in production containers. Their presence strongly indicates either a resource exhaustion attack (DoS) or a crypto mining precursor. |
| `not k8s.ns.name in (kube-system)` | Excludes kube-system namespace. | System namespaces may legitimately run benchmarking tools for node validation. |

---

### 🔗 Defense-in-Depth: How Kyverno and Falco Work Together

| Layer | When It Acts | What It Catches |
|---|---|---|
| **Kyverno** (Admission) | At pod creation/update | Blocks pods without CPU/memory limits — the container can never be scheduled without resource boundaries. |
| **Falco** (Runtime) | When resource abuse tools execute | Detects active resource exhaustion attacks even in containers that have limits. A container with limits can still run `stress-ng`, just within its cgroup boundaries. |

**Key gap Falco covers:** Kyverno ensures limits exist but can't prevent legitimate containers from being exploited. If an attacker gains code execution inside a container (even one with limits), they can run `stress-ng` to consume the container's full allocation. Falco alerts on the execution of these tools, enabling incident response before the container exhausts its limits or triggers OOM kills.

### MITRE ATT&CK Mapping

| Tag | Technique | Description |
|---|---|---|
| `mitre_impact` | **T1499.004 — Endpoint Denial of Service: Application or System Exploitation** | Resource exhaustion tools are used to deny service to other workloads on the same node. |

## Test Scenarios & Manifest Examples

### 1. ✅ PASS Case — Both CPU and Memory Limits Specified
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-limits
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      resources:
        limits:
          cpu: "500m"
          memory: "512Mi"
```
* **Result**: **PASS** — Both `has(limits.cpu)` and `has(limits.memory)` evaluate `true`.

---

### 2. ❌ FAIL Case 1 — Missing CPU Limit (`memory` only)
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-no-cpu-limit
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      resources:
        limits:
          memory: "512Mi"
```
* **Result**: **FAIL** — `has(limits.cpu)` evaluates `false`.

---

### 3. ❌ FAIL Case 2 — Requests Specified, Limits Omitted
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-requests-only
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      resources:
        requests:
          cpu: "100m"
          memory: "128Mi"
```
* **Result**: **FAIL** — `has(c.resources.limits)` evaluates `false`.

---

## How to Test

### Kyverno (Admission Control Dry-Run Check)
```bash
# 1. Test PASS case (both CPU and memory limits present)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-limits
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      resources:
        limits:
          cpu: "500m"
          memory: "512Mi"
EOF

# 2. Test FAIL case (no limits specified)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-no-limits
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
EOF
```

### Falco (Runtime Resource Stress Check)
1. Launch a container executing the `yes` tool:
```bash
kubectl run test-exhaustion --image=alpine --restart=Never -it -- yes > /dev/null
```
2. Verify Falco logs warning alert: `Container Resource Exhaustion Behavior`.
3. Clean up:
```bash
kubectl delete pod test-exhaustion --ignore-not-found
```

