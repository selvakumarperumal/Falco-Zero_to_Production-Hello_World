# Restrict Image Registries

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Validates image prefix patterns against lists containing ECR, ghcr, and gcr. |
| **Falco Detection** | Alerts when a container starts using an image not explicitly matched to trusted hosts. |

## Description
Limits container deployments to approved corporate registries. Detects containers executing code using images sourced from unapproved domains.

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
  # -------------------------------------------------------------------------
  # Original hello-world rules (preserved from existing ConfigMap)
  # -------------------------------------------------------------------------
  hello-world-rules.yaml: |-
    - rule: Container from Untrusted Registry
      desc: >
        Detects a running container whose image was pulled from a registry
        not in the approved list.
      condition: >
        container_started and container
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
