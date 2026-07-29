# Clone Registry Pull Secret

| Property | Value |
|---|---|
| **Type** | Kyverno (GeneratingPolicy — Clone Source Mode) |
| **Kyverno Action** | Automatically clones an image pull secret from `default` namespace into every newly created namespace. Keeps clones synchronized with the source. |
| **Falco Detection** | N/A — this is an operational automation policy. |

## Description
When running private container registries (ECR, GCR, GHCR), every namespace needs an `imagePullSecret` to pull images. Manually creating secrets in each namespace is error-prone and doesn't scale. This `GeneratingPolicy` uses **Clone Source Mode** — it fetches the source secret using `resource.Get()` and replicates it into new namespaces using `generator.Apply()`.

With `synchronize.enabled: true`, any updates to the source secret (e.g., rotated credentials) are automatically propagated to all cloned copies.

### 🛡️ Problem Statement — What Are We Preventing?

In organizations using private container registries, every Kubernetes namespace must have an `imagePullSecret` configured for pods to pull images. Without automated secret distribution, several critical problems arise:

* **ImagePullBackOff Failures**: When a developer creates a new namespace and deploys a workload, the pods fail immediately with `ImagePullBackOff` errors because no registry credential exists in that namespace. This causes deployment delays and frustration, especially during incident response when new namespaces are created urgently.
* **Manual Secret Sprawl**: Cluster administrators must manually run `kubectl create secret` in every new namespace. In clusters with dozens or hundreds of namespaces, this is tedious, error-prone, and creates opportunities for mistyped credentials or forgotten namespaces.
* **Stale Credentials After Rotation**: When registry credentials are rotated (a mandatory security practice, especially for short-lived tokens like AWS ECR auth tokens), administrators must manually update the secret in every namespace. Missing even one namespace causes silent deployment failures when pods are rescheduled.
* **Security Inconsistency**: Without a centralized mechanism, different namespaces may end up with different credentials — some current, some expired, and some with overly broad permissions — creating an inconsistent security posture that is difficult to audit.
* **Multi-Tenant Risk**: In multi-tenant clusters, failing to provision image pull secrets for a tenant namespace can block their entire deployment pipeline or force them to use public images, which introduces supply chain risks.

**Kyverno prevents this** by automatically cloning the source registry secret into every newly created namespace and keeping all copies synchronized with the source. When credentials are rotated in the source, all downstream clones are automatically updated — zero manual intervention required.


---

## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: GeneratingPolicy
metadata:
  name: clone-registry-secret
  annotations:
    policies.kyverno.io/title: Clone Registry Pull Secret
    policies.kyverno.io/category: Supply Chain Security
    policies.kyverno.io/severity: medium
    policies.kyverno.io/description: >-
      Automatically clones an image pull secret from the default namespace
      into every newly created namespace. Uses resource.Get() to fetch the
      source secret and generator.Apply() to create it in the target namespace.
      Synchronization keeps the cloned secret in sync with the source.
  labels:
    app.kubernetes.io/part-of: kyverno-falco-policies
spec:
  evaluation:
    synchronize:
      enabled: true
  matchConstraints:
    resourceRules:
      - apiGroups: ['']
        apiVersions: ['v1']
        operations: [CREATE]
        resources: [namespaces]
  variables:
    - name: targetNs
      expression: 'object.metadata.name'
    - name: sourceSecret
      expression: resource.Get("v1", "secrets", "default", "regcred")
  generate:
    - expression: generator.Apply(variables.targetNs, [variables.sourceSecret])
```

---

## Detailed Explanation

### Clone Source vs Data Source Mode
| Mode | When to Use | CEL Pattern |
|---|---|---|
| **Clone Source** | Copy an existing resource from another namespace | `resource.Get()` + `generator.Apply()` |
| **Data Source** | Create a new resource from inline data | `dyn({...})` + `generator.Apply()` |

### Synchronization
When `synchronize.enabled: true`:
- Updates to the source secret are automatically propagated to all cloned copies.
- Deleting the source secret will delete all downstream clones.
- Deleting the policy will delete all downstream clones (unless `orphanDownstreamOnPolicyDelete: true`).

### CEL Variables
| Variable | Expression | Purpose |
|---|---|---|
| `targetNs` | `object.metadata.name` | The name of the newly created namespace (trigger resource). |
| `sourceSecret` | `resource.Get("v1", "secrets", "default", "regcred")` | Fetches the `regcred` secret from the `default` namespace. |

---

## Prerequisites
1. Create the source secret in the `default` namespace before applying this policy:
```bash
kubectl create secret docker-registry regcred \
  --docker-server=<your-registry> \
  --docker-username=<username> \
  --docker-password=<password> \
  -n default
```

2. Grant secret permissions to the Kyverno background controller via RBAC aggregation (`rbac.kyverno.io/aggregate-to-background-controller: "true"`):
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kyverno:generate-secrets
  labels:
    rbac.kyverno.io/aggregate-to-background-controller: "true"
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
```


## How to Test

### 1. Apply the Policy
```bash
kubectl apply -f kyverno.yaml
```

### 2. Create a New Namespace
```bash
kubectl create namespace test-clone
```

### 3. Verify the Secret Was Cloned
```bash
kubectl get secret regcred -n test-clone
```

### 4. Clean Up
```bash
kubectl delete namespace test-clone
```
