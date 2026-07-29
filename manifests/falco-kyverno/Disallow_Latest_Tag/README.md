# Disallow Latest Tag

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Validates that container and init container images do not end with the `:latest` tag. |
| **Falco Detection** | Detects container start events (`container_started`) where the image repository tag is `latest` or omitted. |

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
container_started and (container.image.tag = "latest" or container.image.tag = "")
```

* **`container_started` Macro**: Fires upon container creation.
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
        container_started and
        (container.image.tag = "latest" or container.image.tag = "")
      output: >
        Container running with :latest tag
        (image=%container.image.repository:%container.image.tag
        pod=%k8s.pod.name ns=%k8s.ns.name)
      priority: NOTICE
      tags: [kyverno_companion, latest_tag, supply_chain]
```

---

## Detailed Explanation

### Kyverno Policy Manifest Explanation
The Kyverno validation enforces image tag discipline at admission time:
- **`validationActions: [Deny]`**: Blocks non-compliant pod creation.
- **CEL Expression**: `containers.all(c, !c.image.endsWith(':latest'))` iterates over all main container specifications, ensuring no image URI ends in `:latest`. Safe handling via `?initContainers.orValue([])` checks init containers if present.

### Falco Rule Manifest Explanation
The companion Falco rule detects `:latest` images at container startup:
- **`container_started`**: Triggers once when a container is initialized by the container runtime.
- **`container.image.tag = "latest" or container.image.tag = ""`**: Checks if the resolved image tag is explicitly `"latest"` or missing (empty string).
- **Priority**: `NOTICE` — logs a notification for security and platform engineering teams to track floating tags in running workloads.

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

