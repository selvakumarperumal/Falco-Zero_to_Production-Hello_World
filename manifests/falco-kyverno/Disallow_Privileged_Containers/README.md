# Disallow Privileged Containers

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Enforces `privileged: false` on container security contexts. |
| **Falco Detection** | Detects container start events where `container.privileged = true`. |

## Description
Prevents deploying containers with full host root level access (`privileged: true`). Tracks and alerts if a privileged container gets spawned.

### 🛡️ Problem Statement — What Are We Preventing?

Setting `privileged: true` in a container's `securityContext` disables virtually all Linux kernel-level isolation mechanisms — the container runs with the same access as processes running directly on the host node. This is the single most dangerous security misconfiguration in Kubernetes:

* **Full Host Access (MITRE ATT&CK: T1611 — Escape to Host)**: A privileged container can access all devices on the host (`/dev`), mount the host filesystem, load kernel modules, and modify kernel parameters via `/proc/sys`. An attacker inside a privileged container can trivially escape to the host node by mounting the host root filesystem and adding SSH keys, cron jobs, or modifying system binaries.
* **Container Escape in One Command**: With privileged mode, escaping the container requires only `nsenter --target 1 --mount --uts --ipc --net --pid` to enter the host's namespaces. This makes privileged containers the easiest and most commonly exploited container escape vector.
* **cgroup and Seccomp Bypass**: Privileged mode disables cgroup resource constraints and seccomp syscall filtering, allowing the container to make any syscall and consume any amount of resources. This defeats all kernel-level sandboxing protections.
* **Network Stack Manipulation**: A privileged container can modify the host's network interfaces, routing tables, and iptables rules — enabling network sniffing, ARP spoofing, and man-in-the-middle attacks against other pods on the same node.
* **Compliance Failure**: Running privileged containers violates the Kubernetes Pod Security Standards (Baseline and Restricted profiles), CIS Kubernetes Benchmark controls, and is explicitly flagged by container security scanners like Trivy, Kubeaudit, and OPA/Gatekeeper.

**Kyverno prevents this** by validating that no container (including init and ephemeral containers) in a pod spec has `privileged: true` set in its `securityContext`, blocking creation at admission time. **Falco detects** any privileged container that bypasses admission controls and starts at runtime, firing a `CRITICAL` alert.


## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: disallow-privileged-containers
  annotations:
    policies.kyverno.io/title: Disallow Privileged Containers
    policies.kyverno.io/category: Pod Security Standards (Baseline)
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      Privileged containers have full access to the host. This policy
      ensures that the privileged flag is never set to true.
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
    - message: "Privileged containers are not allowed."
      expression: >-
        !object.spec.containers.exists(c, has(c.securityContext) && has(c.securityContext.privileged) && c.securityContext.privileged == true) &&
        !object.spec.?initContainers.orValue([]).exists(c, has(c.securityContext) && has(c.securityContext.privileged) && c.securityContext.privileged == true) &&
        !object.spec.?ephemeralContainers.orValue([]).exists(c, has(c.securityContext) && has(c.securityContext.privileged) && c.securityContext.privileged == true)
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
    - rule: Privileged Container Started
      desc: Detects a container spawned with host privileged mode enabled.
      source: syscall
      condition: >
        evt.type in (execve, execveat) and evt.failed = false
        and container and container.privileged = true
      output: >
        Privileged container started (user=%user.name pod=%k8s.pod.name
        ns=%k8s.ns.name image=%container.image.repository)
      priority: CRITICAL
      tags: [kyverno_companion, privileged, mitre_privilege_escalation]
```

## Detailed Explanation

### Kyverno CEL Expression Breakdown

The validation expression must return `true` for the pod to be admitted. It checks three container arrays:

```
!object.spec.containers.exists(c, has(c.securityContext) && has(c.securityContext.privileged) && c.securityContext.privileged == true) &&
!object.spec.?initContainers.orValue([]).exists(c, has(c.securityContext) && has(c.securityContext.privileged) && c.securityContext.privileged == true) &&
!object.spec.?ephemeralContainers.orValue([]).exists(c, has(c.securityContext) && has(c.securityContext.privileged) && c.securityContext.privileged == true)
```

| CEL Fragment | What It Does | Why It's Needed |
|---|---|---|
| `object.spec.containers` | Accesses the list of main containers in the pod spec. | Every pod has at least one main container — this is the primary check target. |
| `.exists(c, ...)` | CEL list macro: returns `true` if **at least one** element `c` satisfies the inner predicate. | We need to find if *any* container in the list has `privileged: true`. |
| `!...exists(...)` | Negates the result — the overall expression returns `true` only if **no** container matches the predicate. | Kyverno requires the expression to return `true` to admit the pod, so we negate "any container is privileged" to mean "no container is privileged." |
| `has(c.securityContext)` | Checks if the `securityContext` field exists on the container. | If the field is missing entirely, accessing `.privileged` on it would cause a CEL evaluation error. `has()` guards against this. |
| `has(c.securityContext.privileged)` | Checks if the `privileged` field exists within `securityContext`. | The `privileged` field is optional in Kubernetes — it defaults to `false` when omitted. We must check existence before comparing its value. |
| `c.securityContext.privileged == true` | Compares the actual value of the `privileged` field. | This is the core security check — if `privileged` is explicitly set to `true`, the container has full host access. |
| `object.spec.?initContainers.orValue([])` | Safe optional field access: if `initContainers` is absent, returns an empty list `[]` instead of erroring. | Pods are not required to have init containers. The `?` operator combined with `.orValue([])` prevents a null reference error on pods without init containers. |
| `object.spec.?ephemeralContainers.orValue([])` | Same pattern for ephemeral (debug) containers. | Ephemeral containers can be added to running pods via `kubectl debug`. They must also be checked for `privileged: true`. |

#### CEL Evaluation Trace — Pod with `privileged: true` on Main Container

```
Step 1: object.spec.containers.exists(c, has(c.securityContext) && ...)
        → c = {name: "app", securityContext: {privileged: true}}
        → has(c.securityContext) = true
        → has(c.securityContext.privileged) = true
        → c.securityContext.privileged == true → true
        → exists returns true
Step 2: !true = false  ← First clause fails
Step 3: Overall expression = false → DENIED
```

#### CEL Evaluation Trace — Pod with No `securityContext`

```
Step 1: object.spec.containers.exists(c, has(c.securityContext) && ...)
        → c = {name: "app", image: "nginx:1.25"}
        → has(c.securityContext) = false
        → Short-circuit: false && ... = false
        → exists returns false (no container matches)
Step 2: !false = true  ← First clause passes
Step 3: (initContainers/ephemeralContainers also pass)
Step 4: Overall expression = true → ADMITTED
```

---

### Falco Condition Breakdown

```
evt.type in (execve, execveat) and evt.failed = false
and container and container.privileged = true
```

| Falco Field | What It Does | Why It's Included |
|---|---|---|
| `evt.type in (execve, execveat)` | Matches the Linux syscalls used to execute a new program. `execve` is the standard exec syscall; `execveat` is the directory-relative variant. | These are the only syscalls that start new processes — by filtering on them, the rule fires exactly once per process execution, not on every syscall the process makes. |
| `evt.failed = false` | Only matches **successful** exec calls (return code ≥ 0). | Failed exec attempts (e.g., binary not found) are not security-relevant — we only care about processes that actually started. |
| `container` | Falco built-in macro that evaluates to `true` when the event originates inside a container context (not the host). | Without this filter, the rule would fire for host-level processes too, which are expected to run with elevated privileges (e.g., `kubelet`). |
| `container.privileged = true` | Checks the container runtime metadata (from containerd/CRI-O) to determine if the container was started with the `--privileged` flag. | This is the core detection — if a privileged container exists at runtime, it means either Kyverno was bypassed or is running in Audit mode. |

---

### 🔗 Defense-in-Depth: How Kyverno and Falco Work Together

| Layer | When It Acts | What It Catches |
|---|---|---|
| **Kyverno** (Admission) | Before the pod is created in the cluster | Blocks any pod manifest with `privileged: true` at the API server level — the pod never gets scheduled. |
| **Falco** (Runtime) | After the container is already running on a node | Detects privileged containers that bypassed admission control. |

**When would the Falco rule fire if Kyverno is active?**
- Kyverno is in **Audit** mode (logging violations but not blocking).
- Kyverno was **temporarily down** (webhook failure policy set to `Ignore`).
- A controller with **elevated RBAC** created pods directly, bypassing the webhook.
- An operator used `--validate=false` or applied resources via a **static pod manifest** on the node (not through the API server).

> If the Falco rule fires while Kyverno is in `Enforce` mode, it indicates a serious security incident — something bypassed the admission layer entirely.

### MITRE ATT&CK Mapping

| Tag | Technique | Description |
|---|---|---|
| `mitre_privilege_escalation` | **T1611 — Escape to Host** | A privileged container can escape to the host by accessing `/dev`, loading kernel modules, or using `nsenter` to enter host namespaces. |

## Test Scenarios & Manifest Examples

### 1. ✅ PASS Case 1 — `privileged: false` Explicitly Set
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-unprivileged
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        privileged: false
```
* **Result**: **PASS** — `c.securityContext.privileged == true` evaluates to `false`.

---

### 2. ✅ PASS Case 2 — `privileged` Field Omitted (Defaults to False)
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-default-unprivileged
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
```
* **Result**: **PASS** — `has(c.securityContext.privileged)` evaluates to `false`, allowing the pod.

---

### 3. ❌ FAIL Case 1 — Main Container Sets `privileged: true`
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-priv-main
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        privileged: true
```
* **Result**: **FAIL** — `c.securityContext.privileged == true` evaluates to `true`, blocking creation.

---

### 4. ❌ FAIL Case 2 — Init Container Sets `privileged: true`
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-priv-init
  namespace: default
spec:
  initContainers:
    - name: setup
      image: busybox:1.36
      securityContext:
        privileged: true
  containers:
    - name: app
      image: nginx:1.25
```
* **Result**: **FAIL** — `!object.spec.?initContainers...exists(c, c.securityContext.privileged == true)` catches the init container.

---

## How to Test

### Kyverno (Admission Control Dry-Run Check)
```bash
# 1. Test PASS case (unprivileged pod should succeed)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-unprivileged
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        privileged: false
EOF

# 2. Test FAIL case (privileged pod should be blocked)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-priv
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        privileged: true
EOF
```

### Falco (Runtime Check)
If admission control is bypassed or in audit mode, verify Falco triggers: `Privileged Container Started`.

