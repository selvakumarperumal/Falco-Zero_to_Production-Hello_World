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
        evt.type in (execve, execveat) and evt.failed = false and container and proc.vpid = 1 and container
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
### Kyverno Policy Manifest Explanation
The policy limits approved image sources:
- **`validations[].expression`**: CEL expression evaluated against `object.spec` containers.
- **`validations[].expression`**: CEL validation rules enforcing compliance.
  - `*.dkr.ecr.*.amazonaws.com/*` (AWS ECR)
  - `ghcr.io/*` (GitHub Container Registry)
  - `gcr.io/*` (Google Container Registry)
  - `registry.k8s.io/*` (Kubernetes Registry)
  - If the image contains a domain not matching this list, the pod creation is blocked.

### Falco Rule Manifest Explanation
The companion Falco rule checks the image tag metadata:
- **`not container.image.repository contains ...`**: Checks the running container's metadata registry string. If it is from an unapproved registry, it triggers an `ERROR` level alert.

## How to Test
### Kyverno (Admission Check)
Try to run a container from an unapproved registry (should be blocked):
```bash
kubectl run test-untrusted-reg --image=quay.io/sysdig/falco --restart=Never
```

### Falco (Runtime Check)
Spawn a container from an untrusted registry (in audit mode/unblocked namespace) and check for: `Container from Untrusted Registry`.
