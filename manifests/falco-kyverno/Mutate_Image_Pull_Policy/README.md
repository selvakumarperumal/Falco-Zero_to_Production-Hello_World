# Mutate Image Pull Policy to Always

| Property | Value |
|---|---|
| **Type** | Kyverno (MutatingPolicy) |
| **Kyverno Prevention** | Mutates pod specifications to change container image pull policies conditional on `:latest` image names. |
| **Falco Detection** | N/A (Admission mutation). |

## Description
Ensures any container specifying the `:latest` tag is updated to use `imagePullPolicy: Always` at admission time. This guarantees that stale cached images are not accidentally reused.

## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: MutatingPolicy
metadata:
  name: mutate-image-pull-policy
  annotations:
    policies.kyverno.io/title: Set Image Pull Policy to Always for Latest
    policies.kyverno.io/category: Supply Chain Security
    policies.kyverno.io/severity: low
    policies.kyverno.io/description: >-
      Automatically sets imagePullPolicy to Always for containers using
      the :latest tag.
  labels:
    app.kubernetes.io/part-of: kyverno-falco-policies
spec:
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: [CREATE, UPDATE]
        resources: [pods]
  mutations:
    - patchStrategicMerge:
        spec:
          containers:
            - (image): "*:latest"
              imagePullPolicy: "Always"
```

## Detailed Explanation
### Kyverno Policy Manifest Explanation
The policy alters configurations automatically:
- **`rules[0].mutate.patchStrategicMerge`**: Configures an inline strategic merge patch.
- **`spec.containers`**: Iterates through containers.
- **`(image): "*:latest"`**: In Kyverno, parenthesis on a field represent a conditional check or anchor. This rule only modifies containers where the image tag ends in `latest`.
- **`imagePullPolicy: "Always"`**: The mutation patch sets the image pull policy to Always for the matched containers.

## How to Test
1. Submit a dry-run server request for a pod using `:latest` without specifying the pull policy:
```bash
kubectl run test-mutate-pull --image=nginx:latest --dry-run=server -o yaml | grep imagePullPolicy
```
2. Confirm the output includes `imagePullPolicy: Always` mutated by Kyverno.
