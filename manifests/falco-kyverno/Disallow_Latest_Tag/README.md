# Disallow Latest Tag

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Validates that container and init container images do not end with the `:latest` tag. |
| **Falco Detection** | Detects container start events where the image repository tag is `latest` or omitted. |

## Description
Ensures all container deployments use explicit, versioned image tags instead of the mutable `:latest` tag to guarantee deployment reproducibility, auditing, and supply chain security. Automatically flags or blocks `:latest` images at admission time and generates runtime alerts upon container initialization.

### 🛡️ Problem Statement — What Are We Preventing?

The `:latest` tag is a mutable pointer that can change at any time, making deployments non-reproducible, unauditable, and vulnerable to supply chain attacks. See the detailed explanation in [Why the :latest Tag is Dangerous in Production](#why-the-latest-tag-is-dangerous-in-production) below.


---

## Why the `:latest` Tag is Dangerous in Production

Using default or mutable tags like `:latest` introduces significant security and operational risks:

* **Non-Reproducible Deployments**: A pod redeployed tomorrow may pull a different underlying image digest than the one deployed today, causing unexpected failures or silent drifting.
* **Supply Chain Vulnerabilities**: If an upstream container registry tag is overwritten (or compromised via a malicious image push), nodes pulling `:latest` will execute unvetted code.
* **Caching and Rollback Failures**: Kubernetes `imagePullPolicy` defaults to `Always` when using `:latest`, causing extra network overhead. Conversely, if cached, nodes may run inconsistent versions across a cluster.
* **Lack of Auditability**: Incident responders cannot easily map a running container to a specific commit or release artifact.

> [!WARNING]
> Disallowing the `:latest` tag is a foundational requirement under **Supply Chain Security Best Practices** and **Pod Security Standards**.

---

## Two-Layer Defense-in-Depth (Kyverno + Falco)

### 1. Kyverno (Admission Time Prevention)
Kyverno evaluates `Pod` `CREATE` and `UPDATE` requests using a CEL expression:

```cel
object.spec.containers.all(c, !c.image.endsWith(':latest')) &&
object.spec.?initContainers.orValue([]).all(c, !c.image.endsWith(':latest'))
```

* **Containers & Init Containers**: Verifies that every container in `containers` and optional `initContainers` does not have an image reference ending with `:latest`.

### 2. Falco (Runtime Detection)
If admission policies are running in `Audit` mode or bypassed, Falco monitors container initialization events at runtime:

```falco
evt.type in (execve, execveat) and evt.failed = false
and container and proc.vpid = 1
and (container.image.tag = "latest" or container.image.tag = "")
```

* **`evt.type in (execve, execveat) and evt.failed = false and container and proc.vpid = 1`**: Fires upon the first process execution in a newly started container (equivalent to the `container_started` macro).
* **Tag Inspection**: Checks if `container.image.tag` is explicitly `"latest"` or blank (which defaults to `latest` in container runtimes), raising a `NOTICE` priority alert.

---

## Kyverno Policy Manifest

```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: disallow-latest-tag
  annotations:
    policies.kyverno.io/title: Disallow Latest Tag
    policies.kyverno.io/category: Supply Chain Security
    policies.kyverno.io/severity: medium
    policies.kyverno.io/description: >-
      Using the :latest tag makes deployments non-reproducible. Require
      explicit version tags.
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
    - message: "An image tag is required and must not be ':latest'."
      expression: >-
        object.spec.containers.all(c, !c.image.endsWith(':latest')) &&
        object.spec.?initContainers.orValue([]).all(c, !c.image.endsWith(':latest'))
```

---

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
    - rule: Container Running with Latest Tag
      desc: >
        Detects a running container using the :latest image tag.
      source: syscall
      condition: >
        evt.type in (execve, execveat) and evt.failed = false
        and container and proc.vpid = 1
        and (container.image.tag = "latest" or container.image.tag = "")
      output: >
        Container running with :latest tag
        (image=%container.image.repository:%container.image.tag
        pod=%k8s.pod.name ns=%k8s.ns.name)
      priority: NOTICE
      tags: [kyverno_companion, latest_tag, supply_chain]
```

---

## Detailed Explanation

### Kyverno CEL Expression Breakdown

```
object.spec.containers.all(c, !c.image.endsWith(':latest')) &&
object.spec.?initContainers.orValue([]).all(c, !c.image.endsWith(':latest'))
```

| CEL Fragment | What It Does | Why It's Needed |
|---|---|---|
| `object.spec.containers.all(c, ...)` | CEL list macro: returns `true` only if **every** container passes the predicate. | Every container in the pod must use a versioned tag — one `:latest` image should block the entire pod. |
| `c.image.endsWith(':latest')` | String method checking if the image reference ends with the literal `:latest` tag. | The `:latest` tag is mutable — it can point to different image digests over time, making deployments non-reproducible. |
| `!c.image.endsWith(':latest')` | Negation — the predicate returns `true` only if the image does **not** end with `:latest`. | Kyverno requires `true` to admit; negating ensures `:latest` images are denied. |
| `object.spec.?initContainers.orValue([])` | Safe optional field access for init containers. | Init containers are optional. `?` with `.orValue([])` returns an empty list if absent, so `.all()` returns `true` (vacuously true for empty lists). |
| `.all(c, !c.image.endsWith(':latest'))` | Same check applied to init containers. | Init containers with `:latest` tags are equally dangerous — they run before the main containers and can pull stale images. |

> **Note:** This expression does not check for images without any tag (e.g., `nginx` without `:tag`). In Kubernetes, untagged images default to `:latest` at pull time, but the string `nginx` does not end with `:latest`. To catch this, use `!c.image.contains(':')` as an additional check.

#### CEL Evaluation Trace — Image with Explicit Version Tag

```
Step 1: c.image = "nginx:1.25" → endsWith(':latest') → false
Step 2: !false = true → container passes
Step 3: .all() returns true → ADMITTED
```

#### CEL Evaluation Trace — Image with `:latest` Tag

```
Step 1: c.image = "nginx:latest" → endsWith(':latest') → true
Step 2: !true = false → container fails
Step 3: .all() returns false → DENIED
```

---

### Falco Condition Breakdown

```
evt.type in (execve, execveat) and evt.failed = false and container
and proc.vpid = 1
and (container.image.tag = "latest" or container.image.tag = "")
```

| Falco Field | What It Does | Why It's Included |
|---|---|---|
| `evt.type in (execve, execveat)` | Matches process execution syscalls. | Standard process start detection. |
| `evt.failed = false` | Only successful executions. | Filters out failed exec attempts. |
| `container` | Event must originate inside a container. | Scopes to containerized workloads. |
| `proc.vpid = 1` | Matches only the container's PID 1 (init process). | Fires exactly once per container start, not for every process inside the container. Without this, the rule would fire repeatedly for every `exec` call. |
| `container.image.tag = "latest"` | The container runtime's resolved image tag is literally `latest`. | Detects explicitly tagged `:latest` images. |
| `container.image.tag = ""` | The image tag is empty (untagged image). | Kubernetes resolves untagged images as `:latest` at pull time, but the tag metadata may be empty in the runtime. This catches that case. |

---

### 🔗 Defense-in-Depth: How Kyverno and Falco Work Together

| Layer | When It Acts | What It Catches |
|---|---|---|
| **Kyverno** (Admission) | At pod creation/update | Blocks pods with `:latest` in the image string before the pod is scheduled. |
| **Falco** (Runtime) | When the container's PID 1 process starts | Detects `:latest` or untagged images that are actually running, even if they bypassed admission. |

**Key gap Falco covers:** Kyverno checks the **string** in the pod spec. If a controller mutates the image tag after admission (or a Helm chart resolves to `:latest` via a template variable), Falco catches the actual running container's image tag from runtime metadata.

### MITRE ATT&CK Mapping

| Tag | Technique | Description |
|---|---|---|
| `supply_chain` | **T1195.002 — Supply Chain Compromise: Software Supply Chain** | Mutable tags enable supply chain attacks — an attacker who compromises a registry can replace the image behind `:latest` without changing the tag name. |

---

## Test Scenarios & Manifest Examples

### 1. ✅ PASS Case — Explicit Version Tag
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-versioned-tag
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25.4
```
* **Result**: **PASS** — Image reference `nginx:1.25.4` does not end with `:latest`.

---

### 2. ❌ FAIL Case 1 — Explicit `:latest` Tag
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-latest-tag
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:latest
```
* **Result**: **FAIL** — `c.image.endsWith(':latest')` evaluates to `true`, violating the validation rule.

---

### 3. ❌ FAIL Case 2 — Init Container Using `:latest`
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-init-latest
  namespace: default
spec:
  initContainers:
    - name: init-task
      image: busybox:latest
  containers:
    - name: app
      image: nginx:1.25.4
```
* **Result**: **FAIL** — `object.spec.?initContainers.orValue([])` checks init containers, rejecting `busybox:latest`.

---

## How to Test

### Kyverno (Admission Control Dry-Run Check)
```bash
# 1. Test PASS case (explicit version tag)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-versioned
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25.4
EOF

# 2. Test FAIL case (:latest tag)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-latest
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:latest
EOF
```

### Falco (Runtime Check)
If admission control is in `Audit` mode or bypassed, starting a container with `:latest` will trigger a Falco notice alert: `Container Running with Latest Tag`.

