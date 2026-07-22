# Require HA Replicas in Production

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy — Advanced CEL) |
| **Kyverno Action** | Denies Deployments with fewer than 2 replicas in production namespaces. Uses `matchConditions`, `messageExpression`, and `namespaceObject` for namespace-aware scoping. |
| **Falco Detection** | N/A — this is a deployment best-practice enforcement policy. |

## Description
Single-replica Deployments in production are a reliability risk — a single pod failure causes complete service downtime. This `ValidatingPolicy` enforces a minimum of 2 replicas for all Deployments, but only in namespaces labeled `environment=production`. It uses advanced CEL features:

- **`matchConditions`** with `namespaceObject` to scope the policy to production namespaces.
- **`messageExpression`** for dynamic, context-rich denial messages that include the actual replica count.

> **Advanced CEL Features Demonstrated:**
> - `namespaceObject.metadata.labels` — Access the namespace object's labels for conditional scoping.
> - `messageExpression` — Dynamic CEL string concatenation for human-readable error messages.
> - `string()` — CEL type casting function to convert integers to strings.

---

## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: require-ha-replicas
  annotations:
    policies.kyverno.io/title: Require HA Replicas in Production
    policies.kyverno.io/category: Best Practices
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      Enforces that Deployments in production namespaces have at least 2
      replicas for high availability. Uses matchConditions to scope to
      namespaces labeled environment=production and messageExpression for
      dynamic denial messages.
  labels:
    app.kubernetes.io/part-of: kyverno-falco-policies
spec:
  validationActions: [Deny]
  matchConstraints:
    resourceRules:
      - apiGroups: [apps]
        apiVersions: [v1]
        operations: [CREATE, UPDATE]
        resources: [deployments]
  matchConditions:
    - name: is-production
      expression: >-
        has(namespaceObject.metadata.labels) &&
        'environment' in namespaceObject.metadata.labels &&
        namespaceObject.metadata.labels['environment'] == 'production'
  validations:
    - expression: 'object.spec.replicas >= 2'
      messageExpression: >-
        "Deployment " + object.metadata.name + " has " +
        string(object.spec.replicas) + " replica(s). Minimum 2 required for HA in production."
      message: "Production deployments must have at least 2 replicas."
```

---

## Detailed Explanation

### `matchConditions` vs `matchConstraints`
| Feature | Purpose |
|---|---|
| `matchConstraints` | Selects resource types (Deployments in apps/v1). Always required. |
| `matchConditions` | Additional CEL filter applied after `matchConstraints`. Policy only activates if ALL conditions return `true`. |

### `messageExpression` vs `message`
| Field | Behavior |
|---|---|
| `message` | Static fallback string shown when validation fails. |
| `messageExpression` | Dynamic CEL expression. If provided and evaluates successfully, overrides `message`. |

Example output when denied:
```
Deployment my-api has 1 replica(s). Minimum 2 required for HA in production.
```

---

## How to Test

### 1. Create a Production Namespace
```bash
kubectl create namespace prod-test
kubectl label namespace prod-test environment=production
```

### 2. Try Creating a Single-Replica Deployment (Should Fail)
```bash
kubectl create deployment test-single --image=nginx:1.25 --replicas=1 -n prod-test
# Expected: Denied — "Deployment test-single has 1 replica(s)..."
```

### 3. Create a Multi-Replica Deployment (Should Succeed)
```bash
kubectl create deployment test-ha --image=nginx:1.25 --replicas=2 -n prod-test
# Expected: deployment.apps/test-ha created
```

### 4. Clean Up
```bash
kubectl delete namespace prod-test
```
