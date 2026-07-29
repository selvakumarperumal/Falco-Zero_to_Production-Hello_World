# Inject Logging Sidecar Container

| Property | Value |
|---|---|
| **Type** | Kyverno (MutatingPolicy — JSONPatch CEL) |
| **Kyverno Action** | Automatically injects a Fluent Bit logging sidecar into pods annotated with `sidecar.kyverno.io/inject=true`. Uses CEL `JSONPatch` mutation with `matchConditions`. |
| **Falco Detection** | N/A — this is an observability automation policy. |

## Description
Centralized logging requires a sidecar container in every application pod to forward logs. Manually adding sidecars to every Deployment manifest is tedious and error-prone. This `MutatingPolicy` uses an **opt-in annotation pattern** — developers add `sidecar.kyverno.io/inject: "true"` to their pods, and Kyverno automatically injects a Fluent Bit sidecar at admission time.

This policy demonstrates **CEL JSONPatch mutation**, which is an alternative to `ApplyConfiguration` for cases where you need to append to arrays (e.g., adding a new container to `spec.containers`).

### 🛡️ Problem Statement — What Are We Preventing?

Centralized logging and observability are non-negotiable in production Kubernetes environments. Without a standardized sidecar injection mechanism, organizations face several critical problems:

* **Inconsistent Log Collection**: When developers are responsible for manually adding logging sidecars to their Deployment manifests, some teams will forget, use different sidecar images, or misconfigure the log forwarding. This results in gaps in centralized log aggregation — during an incident, critical logs from some services may simply be missing.
* **Debugging Blind Spots**: Without consistent log forwarding, incident responders cannot correlate events across microservices. A request that fails as it traverses multiple services becomes untraceable when some services don't export their logs to the central system.
* **Manifest Maintenance Burden**: Manually maintaining sidecar container definitions (image versions, resource limits, volume mounts) across dozens or hundreds of Deployments creates a massive maintenance burden. Updating the Fluent Bit version requires touching every manifest individually.
* **Configuration Drift**: Different teams may use different Fluent Bit versions, configurations, or resource allocations, leading to inconsistent behavior across the cluster. Some sidecars may consume excessive resources while others are under-provisioned and drop logs.
* **Compliance Requirements**: Audit and compliance frameworks (SOC2, HIPAA, PCI-DSS) require comprehensive logging of application activity. Services without log forwarding sidecars represent compliance gaps that can result in audit findings.

**Kyverno prevents this** by automatically injecting a standardized Fluent Bit logging sidecar into every pod that opts in via the `sidecar.kyverno.io/inject: "true"` annotation, ensuring consistent log collection configuration, version management, and resource allocation across the entire cluster.

> **CEL Mutation Types Compared:**
> - `patchType: ApplyConfiguration` — Best for modifying existing fields (labels, resources, etc.)
> - `patchType: JSONPatch` — Best for adding/removing array elements (containers, volumes, etc.)


---

## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: MutatingPolicy
metadata:
  name: inject-sidecar-proxy
  annotations:
    policies.kyverno.io/title: Inject Logging Sidecar Container
    policies.kyverno.io/category: Observability
    policies.kyverno.io/severity: low
    policies.kyverno.io/description: >-
      Automatically injects a Fluent Bit logging sidecar container into pods
      annotated with sidecar.kyverno.io/inject=true. Uses CEL JSONPatch
      mutation with matchConditions for annotation-based opt-in.
  labels:
    app.kubernetes.io/part-of: kyverno-falco-policies
spec:
  matchConstraints:
    resourceRules:
      - apiGroups: ['']
        apiVersions: ['v1']
        operations: [CREATE]
        resources: [pods]
  matchConditions:
    - name: has-sidecar-annotation
      expression: >-
        has(object.metadata.annotations) &&
        'sidecar.kyverno.io/inject' in object.metadata.annotations &&
        object.metadata.annotations['sidecar.kyverno.io/inject'] == 'true'
  mutations:
    - patchType: JSONPatch
      jsonPatch:
        expression: >-
          JSONPatch{op: "add", path: "/spec/containers/-",
            value: Object.spec.containers{
              name: "log-sidecar",
              image: "fluent/fluent-bit:3.2",
              resources: Object.spec.containers.resources{
                requests: {"cpu": "50m", "memory": "64Mi"},
                limits: {"cpu": "100m", "memory": "128Mi"}
              }
            }
          }
```

---

## Detailed Explanation

### `matchConditions` for Opt-In Annotation
```yaml
matchConditions:
  - name: has-sidecar-annotation
    expression: >-
      has(object.metadata.annotations) &&
      'sidecar.kyverno.io/inject' in object.metadata.annotations &&
      object.metadata.annotations['sidecar.kyverno.io/inject'] == 'true'
```
- The policy only fires for pods with the annotation `sidecar.kyverno.io/inject: "true"`.
- Pods without this annotation are unaffected.

### JSONPatch CEL Expression
```
JSONPatch{op: "add", path: "/spec/containers/-", value: Object.spec.containers{...}}
```
- `op: "add"` — JSON Patch add operation.
- `path: "/spec/containers/-"` — Append to the containers array (`-` = end of array).
- `value: Object.spec.containers{...}` — Typed CEL container object with name, image, and resources.

### GitOps Considerations
When using ArgoCD, the injected sidecar will cause drift. Add to your ArgoCD `Application`:
```yaml
spec:
  ignoreDifferences:
    - group: apps
      kind: Deployment
      jsonPointers:
        - /spec/template/spec/containers
```

---

## How to Test

### 1. Create a Pod WITH the Annotation
```bash
kubectl run test-sidecar --image=nginx:1.25 --restart=Never \
  --annotations='sidecar.kyverno.io/inject=true'
```

### 2. Verify Sidecar Was Injected
```bash
kubectl get pod test-sidecar -o jsonpath='{.spec.containers[*].name}'
# Expected: nginx log-sidecar
```

### 3. Create a Pod WITHOUT the Annotation (Should Not Be Mutated)
```bash
kubectl run test-no-sidecar --image=nginx:1.25 --restart=Never
kubectl get pod test-no-sidecar -o jsonpath='{.spec.containers[*].name}'
# Expected: nginx (no sidecar)
```

### 4. Clean Up
```bash
kubectl delete pod test-sidecar test-no-sidecar
```
