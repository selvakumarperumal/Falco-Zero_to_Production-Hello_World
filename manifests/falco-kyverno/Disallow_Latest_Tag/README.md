# Disallow Latest Tag

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Validates that container images do not end in `:latest` and explicitly contain a colon. |
| **Falco Detection** | Detects container start events where the image repository tag is `latest` or blank. |

## Description
Ensures all container deployments use specific version tags instead of the mutable `:latest` tag to ensure reproducibility and tracking. Detects containers starting with `:latest` tag at runtime.

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

      source: syscall
        Detects a running container using the :latest image tag.
      condition: >
        container_started and container
        and (container.image.tag = "latest" or container.image.tag = "")
      output: >
        Container running with :latest tag
        (image=%container.image.repository:%container.image.tag
        pod=%k8s.pod.name ns=%k8s.ns.name)
      priority: NOTICE
      tags: [kyverno_companion, latest_tag, supply_chain]
```

## Detailed Explanation
### Kyverno Policy Manifest Explanation
The Kyverno validation enforces image tag discipline:
- **`image: "!*:latest & *:*"`**:
  - `*:*` requires the image string to contain a colon (meaning a tag or hash is present).
  - `!*:latest` rejects the image if the tag is explicitly `latest`.

### Falco Rule Manifest Explanation
The Falco check detects running configurations that slipped past admission:
- **`container.image.tag = "latest" or container.image.tag = ""`**: Checks the container metadata. If the active running tag is `latest` or undefined, it fires a `NOTICE` level alert to inform administrators of floating versions in production.

## How to Test
### Kyverno (Admission Check)
Attempt to deploy a pod using the latest tag (should be blocked):
```bash
kubectl run test-latest --image=nginx:latest --restart=Never
```

### Falco (Runtime Check)
Start a container running `:latest` (e.g. during an audit rollout) and inspect Falco alerts for: `Container Running with Latest Tag`.
