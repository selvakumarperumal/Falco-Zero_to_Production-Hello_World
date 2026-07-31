# Require Run As Non Root

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Enforces `runAsNonRoot: true` in the container securityContext. |
| **Falco Detection** | Alerts when a spawned process is executed with UID 0 (root) inside namespaces. |

## Description
Ensures containers run as non-root users (UID != 0). Monitors and alerts on root UID execution at runtime.

### 🛡️ Problem Statement — What Are We Preventing?

Running containers as root (UID 0) is one of the most common and dangerous misconfigurations in Kubernetes. Even though containers provide namespace isolation, running as root inside a container significantly increases the impact of any vulnerability:

* **Kernel Exploit Prerequisites**: The most impactful container escape vulnerabilities (CVE-2022-0185, CVE-2022-0847 "Dirty Pipe", CVE-2024-21626 "Leaky Vessels") require root privileges inside the container to exploit. Running as non-root eliminates an entire class of container escape attacks by denying the initial privilege requirement.
* **Full Filesystem Access**: A process running as UID 0 can read and write any file inside the container, including mounted secrets (`/var/run/secrets`), configuration files, and application data. A non-root process is restricted by Linux file permissions, limiting the blast radius of a compromise.
* **Process Manipulation**: Root inside a container can use `ptrace` to attach to other processes, send signals to any process, and modify the process environment — enabling injection attacks, credential harvesting, and process hijacking.
* **Device and Socket Access**: Root can access device files in `/dev`, Unix sockets, and network interfaces that would be restricted for non-root users. This enables attacks like container runtime socket abuse, raw network packet crafting, and storage device manipulation.
* **Compliance Requirement**: The Kubernetes Pod Security Standards (Restricted profile) mandates `runAsNonRoot: true`. CIS Kubernetes Benchmark control 5.2.6 requires running containers as non-root users. NIST SP 800-190 recommends running containers with the least privilege necessary.

**Kyverno prevents this** by validating that pods either set `runAsNonRoot: true` at the pod-level `securityContext` or at the individual container-level `securityContext`, blocking any pod that would run as root. **Falco detects** processes executing with UID 0 inside application containers at runtime, alerting on root execution that bypasses admission controls.


## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: require-run-as-non-root
  annotations:
    policies.kyverno.io/title: Require runAsNonRoot
    policies.kyverno.io/category: Pod Security Standards (Restricted)
    policies.kyverno.io/severity: medium
    policies.kyverno.io/description: >-
      Containers must set runAsNonRoot to true to prevent running as UID 0.
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
    - message: "Containers must not run as root. Set securityContext.runAsNonRoot to true."
      expression: >-
        (has(object.spec.securityContext) && has(object.spec.securityContext.runAsNonRoot) && object.spec.securityContext.runAsNonRoot == true) ||
        object.spec.containers.all(c, has(c.securityContext) && has(c.securityContext.runAsNonRoot) && c.securityContext.runAsNonRoot == true)
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
    - rule: Container Running as Root User
      desc: Detects a process spawned with UID 0 (root) inside an application container.
      source: syscall
      condition: >
        evt.type = execve and
        container and user.uid = 0 and
        not k8s.ns.name in (kube-system, kyverno, falco)
      output: >
        Process running as root in container (user=%user.name uid=%user.uid
        command=%proc.cmdline pod=%k8s.pod.name ns=%k8s.ns.name)
      priority: WARNING
      tags: [kyverno_companion, root_user, mitre_privilege_escalation]
```

## Detailed Explanation

### Kyverno CEL Expression Breakdown

```
(has(object.spec.securityContext) && has(object.spec.securityContext.runAsNonRoot) && object.spec.securityContext.runAsNonRoot == true) ||
object.spec.containers.all(c, has(c.securityContext) && has(c.securityContext.runAsNonRoot) && c.securityContext.runAsNonRoot == true)
```

This expression uses an **OR** (`||`) pattern — the pod passes if `runAsNonRoot: true` is set at **either** the pod level or on **every** individual container:

| CEL Fragment | What It Does | Why It's Needed |
|---|---|---|
| `has(object.spec.securityContext)` | Checks if the pod-level `securityContext` exists. | Guards against null reference — if no pod-level security context exists, we skip to the container-level check. |
| `has(object.spec.securityContext.runAsNonRoot)` | Checks if the `runAsNonRoot` field exists within the pod security context. | The field is optional — it defaults to `false` when omitted. We must verify it exists before comparing. |
| `object.spec.securityContext.runAsNonRoot == true` | Verifies the pod-level `runAsNonRoot` is explicitly set to `true`. | When set at the pod level, it applies to all containers in the pod as a default. This is the preferred configuration. |
| `\|\|` (OR operator) | If the pod-level check passes, the expression short-circuits to `true` without checking individual containers. | Allows two valid configuration patterns: pod-level setting (applies to all containers) or per-container settings. |
| `object.spec.containers.all(c, ...)` | CEL list macro: returns `true` only if **every** container `c` satisfies the predicate. | If the pod-level setting is absent, every container must individually set `runAsNonRoot: true`. |
| `has(c.securityContext) && has(c.securityContext.runAsNonRoot)` | Guards against missing fields at the container level. | Same null-safety pattern as the pod-level check — prevents CEL evaluation errors on containers without a security context. |

#### CEL Evaluation Trace — Pod-Level `runAsNonRoot: true`

```
Step 1: has(object.spec.securityContext) → true
Step 2: has(object.spec.securityContext.runAsNonRoot) → true
Step 3: object.spec.securityContext.runAsNonRoot == true → true
Step 4: Left side of || = true → SHORT-CIRCUIT → ADMITTED
        (container-level check is never evaluated)
```

#### CEL Evaluation Trace — No `runAsNonRoot` Anywhere

```
Step 1: has(object.spec.securityContext) → false
Step 2: Left side of || = false → evaluate right side
Step 3: object.spec.containers.all(c, has(c.securityContext) && ...) 
        → c = {name: "app"} → has(c.securityContext) = false → false
        → all returns false (not all containers pass)
Step 4: false || false = false → DENIED
```

---

### Falco Condition Breakdown

```
evt.type in (execve, execveat) and evt.failed = false and container
and user.uid = 0
and not k8s.ns.name in (kube-system, kyverno)
```

| Falco Field | What It Does | Why It's Included |
|---|---|---|
| `evt.type in (execve, execveat)` | Matches process execution syscalls. | Fires once per new process — detects the moment a root-UID process starts inside a container. |
| `evt.failed = false` | Only successful process executions. | Failed exec calls don't pose a security risk. |
| `container` | Event must originate inside a container. | Host processes often run as root legitimately (kubelet, containerd). |
| `user.uid = 0` | The process's effective user ID is root. | This is the core detection — even if `runAsNonRoot` was set, the image might have `USER root` in its Dockerfile, or a process might use `setuid` to escalate. |
| `not k8s.ns.name in (kube-system, kyverno)` | Excludes system namespaces. | System components (kube-proxy, CoreDNS, Kyverno itself) legitimately run as root. Alerting on them would create noise. |

---

### 🔗 Defense-in-Depth: How Kyverno and Falco Work Together

| Layer | When It Acts | What It Catches |
|---|---|---|
| **Kyverno** (Admission) | At pod creation/update | Blocks pods that don't explicitly set `runAsNonRoot: true` — but cannot verify the container image's actual USER directive. |
| **Falco** (Runtime) | When a process executes | Detects **actual** root-UID execution, catching cases where `runAsNonRoot: true` is set but the image's entrypoint still runs as root (Kubernetes will reject these too, but only at container start, not at admission). |

**Key gap Falco covers:** Kyverno validates the *intent* (the `runAsNonRoot` field), but Falco validates the *reality* (actual UID at runtime). A container could have `runAsNonRoot: true` but use a `setuid` binary to escalate to UID 0 after startup — only Falco catches this.

### MITRE ATT&CK Mapping

| Tag | Technique | Description |
|---|---|---|
| `mitre_privilege_escalation` | **T1611 — Escape to Host** | Running as root inside a container is a prerequisite for most container escape exploits (Dirty Pipe, Leaky Vessels). |

## Test Scenarios & Manifest Examples

### 1. ✅ PASS Case 1 — Pod-Level `runAsNonRoot: true`
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-pod-non-root
  namespace: default
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
  containers:
    - name: app
      image: nginx:1.25
```
* **Result**: **PASS** — `object.spec.securityContext.runAsNonRoot == true` evaluates `true`.

---

### 2. ✅ PASS Case 2 — Container-Level `runAsNonRoot: true`
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-container-non-root
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
```
* **Result**: **PASS** — `c.securityContext.runAsNonRoot == true` for all containers evaluates `true`.

---

### 3. ❌ FAIL Case — Default Execution (Omitted `runAsNonRoot`)
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-root-default
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
```
* **Result**: **FAIL** — `runAsNonRoot` is not configured at pod or container level.

---

## How to Test

### Kyverno (Admission Control Dry-Run Check)
```bash
# 1. Test PASS case (non-root configuration)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-non-root
  namespace: default
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
  containers:
    - name: app
      image: nginx:1.25
EOF

# 2. Test FAIL case (root default pod)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-root
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
EOF
```

### Falco (Runtime Root Process Check)
1. Spawn a container running as root (UID 0):
```bash
kubectl run test-root-check --image=alpine --restart=Never -it -- id
```
2. Verify Falco triggers warning alert: `Container Running as Root User`.
3. Clean up:
```bash
kubectl delete pod test-root-check --ignore-not-found
```

