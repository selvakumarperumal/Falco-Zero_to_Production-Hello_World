# Add PSS Labels to Namespaces

| Property | Value |
|---|---|
| **Type** | Kyverno (MutatingPolicy) |
| **Kyverno Prevention** | Mutates namespaces to add enforcement and warning labels for pod security standards. |
| **Falco Detection** | N/A (Metadata mutation, no corresponding runtime execution). |

## Description
Automatically adds Pod Security Standard labels (`pod-security.kubernetes.io/enforce: baseline`) to newly created namespaces. This enforces a baseline level of pod security at the namespace level by default.

### 🛡️ Problem Statement — What Are We Preventing?

By default, newly created Kubernetes namespaces have **no Pod Security Standards enforcement**. This means any pod — including those running as root, using privileged mode, or sharing host namespaces — can be deployed without restriction. This is a critical security gap:

* **Unrestricted Workloads**: Without PSS labels, an attacker who gains access to deploy pods in a namespace can run privileged containers, mount host filesystems, or escalate privileges with zero resistance from the Kubernetes admission layer.
* **Human Error**: Developers may create new namespaces for testing or feature work and forget to manually apply security labels, leaving production-adjacent environments wide open.
* **Compliance Drift**: Organizations requiring baseline or restricted pod security profiles (e.g., for CIS Kubernetes Benchmark, SOC2, or PCI-DSS compliance) cannot guarantee consistent enforcement unless every namespace is automatically labeled.
* **Lateral Movement**: In a multi-tenant cluster, an unlabeled namespace becomes a landing zone where compromised workloads from other namespaces can be redeployed without the security controls that exist elsewhere.

**Kyverno prevents this** by automatically mutating every newly created namespace to include `pod-security.kubernetes.io/enforce: baseline` and `pod-security.kubernetes.io/warn: restricted` labels, ensuring that Kubernetes' built-in Pod Security Admission controller enforces security standards from the moment a namespace is created — without any manual intervention.


## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: MutatingPolicy
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
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: [CREATE]
        resources: [namespaces]
  mutations:
    - patchType: ApplyConfiguration
      applyConfiguration:
        expression: >-
          Object{
            metadata: Object.metadata{
              labels: {
                "pod-security.kubernetes.io/enforce": "baseline",
                "pod-security.kubernetes.io/enforce-version": "latest",
                "pod-security.kubernetes.io/warn": "restricted",
                "pod-security.kubernetes.io/warn-version": "latest"
              }
            }
          }
```

## Detailed Explanation
### Kyverno Policy Manifest Explanation
The policy modifies `Namespace` objects at creation time:
- **`metadata.name: add-pss-labels`**: The policy name.
- **`matchConstraints`**: Specifies target resources and operations (e.g. Pods/Namespaces on CREATE/UPDATE).
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
