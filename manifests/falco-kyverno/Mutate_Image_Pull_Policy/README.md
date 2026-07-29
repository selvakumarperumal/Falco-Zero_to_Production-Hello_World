# Mutate Image Pull Policy to Always

| Property | Value |
|---|---|
| **Type** | Kyverno (MutatingPolicy) |
| **Kyverno Prevention** | Mutates pod specifications to change container image pull policies conditional on `:latest` image names. |
| **Falco Detection** | N/A (Admission mutation). |

## Description
Ensures any container specifying the `:latest` tag is updated to use `imagePullPolicy: Always` at admission time. This guarantees that stale cached images are not accidentally reused.

### 🛡️ Problem Statement — What Are We Preventing?

When containers use the `:latest` tag with the default `imagePullPolicy` of `IfNotPresent`, Kubernetes only pulls the image if it doesn't already exist in the node's local cache. This creates a dangerous combination of problems:

* **Stale Image Execution**: Different nodes in the cluster may have different cached versions of the `latest` tag. When pods are rescheduled to different nodes, they silently run different image versions — creating inconsistent application behavior across the cluster that is extremely difficult to debug.
* **Tag Hijacking Blindness (MITRE ATT&CK: T1525)**: If an attacker compromises a container registry and overwrites the `:latest` tag with a malicious image, nodes using `IfNotPresent` will continue running the old (safe) cached image while new nodes or pods will pull the compromised version. This creates a split-brain scenario where some pods are compromised and others are not, making detection harder.
* **Rollback Failure**: When using `:latest` with `IfNotPresent`, rolling back a deployment doesn't actually change the running image — the node's cache still contains the same tag. Teams believe they've rolled back, but the application continues running the problematic version.
* **CI/CD Pipeline Inconsistency**: Build pipelines that push to `:latest` expect their latest code to be deployed. But with `IfNotPresent`, Kubernetes may skip the pull entirely and run a days-old cached image, causing confusion when newly deployed code doesn't appear to take effect.
* **Security Patch Gaps**: When critical security patches are applied by rebuilding and pushing to `:latest`, nodes with cached images won't pull the patched version, leaving vulnerable images running indefinitely.

**Kyverno prevents this** by automatically mutating the `imagePullPolicy` to `Always` for any container using the `:latest` tag or an untagged image reference, ensuring that every pod start pulls the freshest image from the registry — eliminating stale cache issues without requiring developers to remember to set the pull policy.


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
    - patchType: ApplyConfiguration
      applyConfiguration:
        expression: >-
          Object{
            spec: Object.spec{
              containers: object.spec.containers.map(c,
                c.image.endsWith(':latest') || !c.image.contains(':') ?
                  Object.spec.containers{
                    name: c.name,
                    imagePullPolicy: 'Always'
                  } :
                  Object.spec.containers{
                    name: c.name
                  }
              )
            }
          }
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
