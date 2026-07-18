# Add PSS Labels to Namespaces

| Property | Value |
|---|---|
| **Type** | Kyverno (Mutation) |
| **Kyverno Prevention** | Mutates namespaces to add enforcement and warning labels for pod security standards. |
| **Falco Detection** | N/A (Metadata mutation, no corresponding runtime execution). |

## Description
Automatically adds Pod Security Standard labels (`pod-security.kubernetes.io/enforce: baseline`) to newly created namespaces. This enforces a baseline level of pod security at the namespace level by default.

## Kyverno Policy Manifest
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: add-pss-labels
  annotations:
    policies.kyverno.io/title: Add Pod Security Standards Labels
    policies.kyverno.io/category: Pod Security Standards
    policies.kyverno.io/severity: medium
    policies.kyverno.io/description: >-
      Automatically adds Pod Security Standard labels to new namespaces
      to enforce baseline security at the namespace level.
  labels:
    app.kubernetes.io/part-of: kyverno-falco-policies
spec:
  rules:
    - name: add-pss-baseline
      match:
        any:
          - resources:
              kinds:
                - Namespace
      exclude:
        any:
          - resources:
              namespaces:
                - kube-system
                - kube-public
                - kube-node-lease
      mutate:
        patchStrategicMerge:
          metadata:
            labels:
              pod-security.kubernetes.io/enforce: "baseline"
              pod-security.kubernetes.io/enforce-version: "latest"
              pod-security.kubernetes.io/warn: "restricted"
              pod-security.kubernetes.io/warn-version: "latest"
```

## Detailed Explanation
### Kyverno Policy Manifest Explanation
The policy modifies `Namespace` objects at creation time:
- **`metadata.name: add-pss-labels`**: The policy name.
- **`rules[0].match.any.resources.kinds: [Namespace]`**: Restricts this rule to trigger only when a Namespace is created or updated.
- **`rules[0].exclude`**: Prevents the mutation of system namespaces (`kube-system`, `kube-public`, `kube-node-lease`) to avoid breaking existing system-critical configurations.
- **`rules[0].mutate`**: Applies a patch using `patchStrategicMerge`.
- **`metadata.labels`**: Injects labels that enable Kubernetes native Pod Security Admission:
  - `pod-security.kubernetes.io/enforce: baseline`: Rejects any pods that violate the baseline security standard (e.g. running privileged containers, sharing host namespaces).
  - `pod-security.kubernetes.io/warn: restricted`: Warns users if they run a pod violating the stricter restricted standard (e.g. running as root).

## How to Test
1. Create a test namespace:
```bash
kubectl create namespace test-pss
```
2. Verify that Kyverno has automatically mutated the namespace to include the baseline and restricted PSS labels:
```bash
kubectl get namespace test-pss --show-labels
```
3. Clean up:
```bash
kubectl delete namespace test-pss
```
