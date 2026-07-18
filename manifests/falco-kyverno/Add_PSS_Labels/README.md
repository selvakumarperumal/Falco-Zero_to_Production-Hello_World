# Add PSS Labels to Namespaces

| Property | Value |
|---|---|
| **Type** | Kyverno (Mutation) |
| **Kyverno Prevention** | Mutates namespaces to add enforcement and warning labels for pod security standards. |
| **Falco Detection** | N/A (Metadata mutation, no corresponding runtime execution). |

## Description
Automatically adds Pod Security Standard labels (`pod-security.kubernetes.io/enforce: baseline`) to newly created namespaces. This enforces a baseline level of pod security at the namespace level by default.

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
