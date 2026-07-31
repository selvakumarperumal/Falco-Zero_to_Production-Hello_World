# Restrict Image Registries

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Validates image prefix patterns against lists containing ECR, ghcr, and gcr. |
| **Falco Detection** | Alerts when a container starts using an image not explicitly matched to trusted hosts. |

## Description
Limits container deployments to approved corporate registries. Detects containers executing code using images sourced from unapproved domains.

### 🛡️ Problem Statement — What Are We Preventing?

Allowing pods to pull container images from any registry on the internet is one of the most significant supply chain risks in Kubernetes. Without registry restrictions, any developer can deploy containers from untrusted sources, introducing severe security threats:

* **Malicious Image Injection (MITRE ATT&CK: T1525)**: Public container registries (Docker Hub, Quay.io, etc.) host millions of images, many of which contain embedded malware, crypto miners, backdoors, or vulnerable software. An attacker can publish a malicious image with a convincing name (e.g., `nginx-optimized`) and wait for developers to pull it.
* **Typosquatting Attacks**: Attackers register image names that are slight misspellings of popular images (e.g., `ngixn/nginx`, `ubunty/ubuntu`). A developer who makes a typo in their Deployment manifest unknowingly deploys a compromised image.
* **Supply Chain Poisoning**: Even legitimate public images may be compromised by upstream supply chain attacks. By restricting to curated corporate registries (ECR, GCR, GHCR), organizations ensure that only images that have passed internal security scanning, vulnerability assessment, and approval workflows are deployed.
* **Data Exfiltration via Image Layers**: A malicious image can include hidden processes that exfiltrate environment variables, mounted secrets, and service account tokens at container startup — before any runtime security tool has a chance to detect the activity.
* **Compliance and Audit Requirements**: Security standards (NIST SP 800-190, CIS Kubernetes Benchmark 5.5.1, FedRAMP) require that organizations maintain an approved list of container image sources and block deployment from unapproved registries. Using unrestricted registries fails these audit controls.

**Kyverno prevents this** by validating that all container images in a pod spec come from approved registries (ECR, ghcr.io, gcr.io, registry.k8s.io, docker.io), blocking pods that reference images from unapproved sources. **Falco detects** containers running images from untrusted registries at runtime, alerting on workloads that bypassed admission controls.


## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: restrict-image-registries
  annotations:
    policies.kyverno.io/title: Restrict Image Registries
    policies.kyverno.io/category: Supply Chain Security
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      Images may only be pulled from approved registries.
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
    - message: "Images must come from an approved registry (ECR, ghcr.io, gcr.io, or registry.k8s.io)."
      expression: >-
        object.spec.containers.all(c,
          c.image.contains('.dkr.ecr.') ||
          c.image.startsWith('ghcr.io/') ||
          c.image.startsWith('gcr.io/') ||
          c.image.startsWith('registry.k8s.io/') ||
          c.image.startsWith('docker.io/') ||
          !c.image.contains('/')
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
    - rule: Container from Untrusted Registry
      desc: >
        Detects a running container whose image was pulled from a registry
        not in the approved list.
      source: syscall
      condition: >
        evt.type in (execve, execveat) and evt.failed = false and container and proc.vpid = 1
        and not container.image.repository contains "dkr.ecr"
        and not container.image.repository contains "ghcr.io"
        and not container.image.repository contains "gcr.io"
        and not container.image.repository contains "registry.k8s.io"
      output: >
        Container from untrusted registry
        (image=%container.image.repository:%container.image.tag
        pod=%k8s.pod.name ns=%k8s.ns.name)
      priority: ERROR
      tags: [kyverno_companion, supply_chain, mitre_initial_access]
```

## Detailed Explanation

### Kyverno CEL Expression Breakdown

```
object.spec.containers.all(c,
  c.image.contains('.dkr.ecr.') ||
  c.image.startsWith('ghcr.io/') ||
  c.image.startsWith('gcr.io/') ||
  c.image.startsWith('registry.k8s.io/') ||
  c.image.startsWith('docker.io/') ||
  !c.image.contains('/')
)
```

| CEL Fragment | What It Does | Why It's Needed |
|---|---|---|
| `object.spec.containers.all(c, ...)` | CEL list macro: returns `true` only if **every** container `c` satisfies the inner predicate. | All containers must use approved registries — even one container from an unapproved source should block the pod. |
| `c.image.contains('.dkr.ecr.')` | Checks if the image string contains the AWS ECR domain pattern. | ECR URLs follow `<account>.dkr.ecr.<region>.amazonaws.com/<image>` — using `.contains()` matches any AWS account and region. |
| `c.image.startsWith('ghcr.io/')` | Checks if the image starts with the GitHub Container Registry prefix. | `startsWith` is more precise than `contains` here — it prevents an attacker from embedding `ghcr.io` in a subdomain of a malicious registry. |
| `c.image.startsWith('gcr.io/')` | Google Container Registry prefix check. | Same logic — ensures the image is truly from GCR, not a domain containing `gcr.io` elsewhere. |
| `c.image.startsWith('registry.k8s.io/')` | Kubernetes official registry prefix check. | System images (CoreDNS, kube-proxy, etc.) come from this registry. |
| `c.image.startsWith('docker.io/')` | Docker Hub fully-qualified prefix check. | Allows Docker Hub images when explicitly qualified with `docker.io/`. |
| `!c.image.contains('/')` | Accepts images without a domain prefix (e.g., `nginx:1.25`). | Short-form images like `nginx` or `busybox` are implicitly from Docker Hub. Since they have no `/` separator, they don't match any registry prefix — this clause handles the special case. |
| `\|\|` (OR chain) | The image must match **at least one** approved registry pattern. | Uses OR logic so each registry is an additional allowed source. |

#### CEL Evaluation Trace — Image from Approved Registry

```
Step 1: c.image = "ghcr.io/myorg/myapp:v1.2.3"
Step 2: c.image.contains('.dkr.ecr.') → false
Step 3: c.image.startsWith('ghcr.io/') → true → SHORT-CIRCUIT
Step 4: Predicate returns true for this container
Step 5: .all() checks next container (if any) → all true → ADMITTED
```

#### CEL Evaluation Trace — Image from Unapproved Registry

```
Step 1: c.image = "evil-registry.io/malicious/backdoor:latest"
Step 2: All contains/startsWith checks → false
Step 3: !c.image.contains('/') → !'evil-registry.io/...' contains '/' → !true → false
Step 4: Predicate returns false → .all() returns false → DENIED
```

---

### Falco Condition Breakdown

```
evt.type in (execve, execveat) and evt.failed = false and container
and not container.image.repository contains "dkr.ecr"
and not container.image.repository contains "ghcr.io"
and not container.image.repository contains "gcr.io"
and not container.image.repository contains "registry.k8s.io"
```

| Falco Field | What It Does | Why It's Included |
|---|---|---|
| `evt.type in (execve, execveat)` | Matches process execution syscalls. | Fires when a process starts inside the container, confirming it's actually running. |
| `evt.failed = false` | Only successful executions. | We only care about containers that are actually running code. |
| `container` | Event must originate inside a container. | Scopes detection to containerized workloads only. |
| `container.image.repository` | The image registry/repository string as reported by the container runtime (containerd/CRI-O). | This is the actual image the container is running — it comes from runtime metadata, not the pod spec, so it cannot be spoofed at the Kubernetes API level. |
| `not ... contains "dkr.ecr"` | Excludes AWS ECR images from alerting. | Same approved registry list as Kyverno — images from ECR are trusted. |
| `not ... contains "ghcr.io"` / `"gcr.io"` / `"registry.k8s.io"` | Excludes other approved registries. | Each `not contains` clause acts as a safelist entry. An alert fires only if the image doesn't match **any** approved registry. |

---

### 🔗 Defense-in-Depth: How Kyverno and Falco Work Together

| Layer | When It Acts | What It Catches |
|---|---|---|
| **Kyverno** (Admission) | At pod creation/update | Blocks pods whose image strings don't match approved registry patterns. Validates the **declared** image. |
| **Falco** (Runtime) | When a process runs inside the container | Detects containers running images from unapproved registries. Validates the **actual** image from container runtime metadata. |

**Key gap Falco covers:** Kyverno validates the image string in the pod spec, but cannot verify what image the container runtime actually pulled. In rare scenarios (image tag mutation, registry compromise, or manual container injection), the runtime image may differ from the declared spec. Falco checks the actual container runtime metadata.

### MITRE ATT&CK Mapping

| Tag | Technique | Description |
|---|---|---|
| `mitre_initial_access` | **T1525 — Implant Container Image** | Attackers publish malicious images on public registries to gain initial access when unsuspecting teams pull and deploy them. |

## Test Scenarios & Manifest Examples

### 1. ✅ PASS Case 1 — GitHub Container Registry (`ghcr.io`)
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-ghcr
  namespace: default
spec:
  containers:
    - name: app
      image: ghcr.io/my-org/my-app:v1.0.0
```
* **Result**: **PASS** — `c.image.startsWith('ghcr.io/')` evaluates `true`.

---

### 2. ✅ PASS Case 2 — Official Docker Hub Image (`!c.image.contains('/')`)
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-library-image
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
```
* **Result**: **PASS** — `!c.image.contains('/')` evaluates `true` for standard library images (e.g. `nginx:1.25`).

---

### 3. ❌ FAIL Case — Unapproved Registry (`quay.io`)
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-untrusted-registry
  namespace: default
spec:
  containers:
    - name: app
      image: quay.io/sysdig/falco:latest
```
* **Result**: **FAIL** — `quay.io` domain does not match any allowed prefix in the policy expression.

---

## How to Test

### Kyverno (Admission Control Dry-Run Check)
```bash
# 1. Test PASS case (approved ghcr.io registry)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-ghcr
  namespace: default
spec:
  containers:
    - name: app
      image: ghcr.io/org/app:1.0
EOF

# 2. Test FAIL case (unapproved quay.io registry)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-quay
  namespace: default
spec:
  containers:
    - name: app
      image: quay.io/sysdig/falco:latest
EOF
```

### Falco (Runtime Registry Check)
If admission control is in Audit mode, running a container from an untrusted registry like `quay.io` triggers Falco error alert: `Container from Untrusted Registry`.

