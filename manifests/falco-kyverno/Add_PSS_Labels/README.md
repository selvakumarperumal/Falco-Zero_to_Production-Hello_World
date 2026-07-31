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

### Kyverno CEL Expression Breakdown

```yaml
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

| CEL Fragment | What It Does | Why It's Needed |
|---|---|---|
| `patchType: ApplyConfiguration` | Applies Server-Side Apply Object patch structure. | Merges labels safely into the target namespace's existing metadata map. |
| `"pod-security.kubernetes.io/enforce": "baseline"` | Sets Kubernetes native Pod Security Admission enforce level to `baseline`. | Prevents pods violating Baseline Pod Security Standards (e.g. privileged, host namespaces) from running. |
| `"pod-security.kubernetes.io/enforce-version": "latest"` | Sets PSS enforce version pin to `latest`. | Evaluates against latest Kubernetes PSS rules. |
| `"pod-security.kubernetes.io/warn": "restricted"` | Sets PSS warning level to `restricted`. | Emits warnings on `kubectl apply` for pods violating Restricted PSS profile (e.g. running as root). |

---

### ℹ️ Why There Is No Falco Companion Rule

Namespace security labeling is a metadata admission-time operation that enables Kubernetes built-in Pod Security Admission (PSA).

* **Metadata Concern**: Labels are Kubernetes API metadata.
* **Runtime Controls Handled**: Runtime enforcement of actual pod security behavior (privileged, root user, capabilities) is handled individually by runtime Falco rules in companion policy directories.

---

## Test Scenarios & Manifest Examples

### 1. ✅ Mutated PASS Case — New Namespace Receives Baseline & Warn PSS Labels
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: test-app-ns
```
* **Result**: **MUTATED** — Kyverno intercepts creation and applies the following labels:
  - `pod-security.kubernetes.io/enforce: "baseline"`
  - `pod-security.kubernetes.io/enforce-version: "latest"`
  - `pod-security.kubernetes.io/warn: "restricted"`
  - `pod-security.kubernetes.io/warn-version: "latest"`

---

### 2. ✅ Explicit Custom Labels Preserved
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: test-custom-ns
  labels:
    team: backend
    environment: staging
```
* **Result**: **MUTATED & MERGED** — Custom labels `team: backend` and `environment: staging` are retained while PSS labels are merged via `ApplyConfiguration`.

---

## How to Test

### Kyverno (Admission Control Dry-Run Check)
Test against the admission webhook using server dry-run to observe the mutated output without persisting resources:

```bash
# Test namespace creation and inspect mutated labels
kubectl create namespace test-pss-dryrun --dry-run=server -o yaml | grep -A 6 labels
```

*Expected Output:*
```yaml
  labels:
    kubernetes.io/metadata.name: test-pss-dryrun
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: latest
```

