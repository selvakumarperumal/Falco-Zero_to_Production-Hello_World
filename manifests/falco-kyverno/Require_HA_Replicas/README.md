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

### 🛡️ Problem Statement — What Are We Preventing?

Running Deployments with a single replica in production creates a single point of failure that can cause complete service outages. This is a fundamental reliability anti-pattern:

* **Zero-Downtime Failure**: When a single-replica pod is terminated (node failure, OOM kill, preemption, or eviction), the service becomes completely unavailable until Kubernetes schedules and starts a replacement pod. Depending on image pull times, health check startup probes, and readiness gates, this downtime can range from seconds to minutes.
* **Rolling Update Failures**: Kubernetes rolling updates work by scaling up new pods before scaling down old ones. With only 1 replica, rolling updates temporarily have zero running instances during the transition, causing brief but repeated outages on every deployment.
* **Node Failure Blast Radius**: If the single node hosting a single-replica pod fails (hardware failure, kernel panic, spot instance reclaim), the pod is lost entirely. The Kubernetes scheduler must find a new node, pull the image, and pass readiness checks — a process that can take several minutes in large clusters.
* **SLA Violations**: Production services typically have uptime SLAs (99.9% = ~8.7 hours/year, 99.95% = ~4.4 hours/year). A single node failure causing 5+ minutes of downtime per incident quickly exhausts the annual downtime budget if the service has only one replica.
* **Pod Disruption Budget Ineffectiveness**: PodDisruptionBudgets (PDBs) are meaningless with a single replica — there's no way to maintain availability during voluntary disruptions (node drains, cluster upgrades) when there's only one pod to begin with.

**Kyverno prevents this** by validating that all Deployments in production namespaces (labeled `environment=production`) have at least 2 replicas, ensuring high availability and resilience against individual pod or node failures.

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

## Test Scenarios & Manifest Examples

### 1. ✅ PASS Case 1 — Production Deployment with HA Replicas (`replicas: 2`)
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-ha-deployment
  namespace: prod-ns
spec:
  replicas: 2
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: app
          image: nginx:1.25
```
* **Result**: **PASS** — Target namespace has label `environment: production` (`matchConditions` evaluates `true`). `object.spec.replicas >= 2` evaluates `true`.

---

### 2. ❌ FAIL Case — Production Deployment with Single Replica (`replicas: 1`)
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-single-replica-prod
  namespace: prod-ns
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: app
          image: nginx:1.25
```
* **Result**: **FAIL** — Denied with dynamic message: `"Deployment test-single-replica-prod has 1 replica(s). Minimum 2 required for HA in production."`

---

### 3. 🛡️ EXEMPT CASE — Staging Namespace (`environment: staging`)
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-single-replica-staging
  namespace: staging-ns
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: app
          image: nginx:1.25
```
* **Result**: **PASS (EXEMPT)** — `matchConditions` evaluates `false` because `namespaceObject.metadata.labels['environment'] != 'production'`. Single-replica deployments are permitted in non-production environments.

---

## How to Test

### Kyverno (Admission Control Dry-Run Check)
```bash
# 1. Setup labeled test namespaces
kubectl create namespace prod-test --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace prod-test environment=production --overwrite

kubectl create namespace staging-test --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace staging-test environment=staging --overwrite

# 2. Test FAIL case in production namespace (should be denied)
kubectl apply -f - -n prod-test --dry-run=server <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-single
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: app
          image: nginx:1.25
EOF

# 3. Test PASS case in production namespace (2 replicas)
kubectl apply -f - -n prod-test --dry-run=server <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-ha
spec:
  replicas: 2
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: app
          image: nginx:1.25
EOF

# 4. Clean up test namespaces
kubectl delete namespace prod-test staging-test --ignore-not-found
```

