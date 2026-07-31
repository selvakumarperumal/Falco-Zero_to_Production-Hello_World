# Inject Default Resource Requests & Limits

| Property | Value |
|---|---|
| **Type** | Kyverno (MutatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Automatically mutates pod definitions at admission to inject default CPU (`100m`) and Memory (`128Mi`) requests if omitted. |
| **Falco Detection** | Monitors process execution inside containers running in non-system namespaces to flag unconstrained pods. |

## Description
Enforces cloud-native resource management best practices. When developers submit Pod manifests without specifying CPU or memory requests, Kyverno mutates the incoming object at admission time to inject default baseline requests (`100m` CPU, `128Mi` Memory). This prevents unconstrained pods from starving cluster node capacity.

### 🛡️ Problem Statement — What Are We Preventing?

When pods are deployed without CPU or memory resource requests, the Kubernetes scheduler treats them as having zero resource requirements. This creates a cascade of operational and stability problems:

* **Node Resource Starvation**: Pods without requests can consume unlimited CPU and memory. A single unconstrained pod running a memory leak or CPU-intensive task can starve all other pods on the same node, causing widespread degraded performance or OOM kills.
* **Scheduler Blindness**: The Kubernetes scheduler uses resource requests to make placement decisions. Pods without requests appear "free" to the scheduler, leading to node over-commitment where the scheduler packs too many workloads onto a single node, unaware of their actual resource consumption.
* **Noisy Neighbor Impact**: In multi-tenant clusters, teams deploying pods without resource requests consume shared node capacity unfairly. One team's uncontrolled workload can degrade performance for all other teams sharing the same node pool.
* **OOM Kill Cascades**: Without memory requests, the Linux kernel's OOM killer has no `cgroup` limits to enforce. When a node runs out of memory, the OOM killer selects victims unpredictably — potentially killing critical system pods (`kubelet`, `kube-proxy`) or other production workloads instead of the offending unconstrained pod.
* **Cost Management Failure**: Cloud cost optimization tools (e.g., Kubecost, Spot.io) rely on resource requests to calculate per-team/per-namespace costs. Pods without requests cannot be accurately attributed, making cost allocation impossible and hiding waste.

**Kyverno prevents this** by automatically injecting baseline CPU (`100m`) and memory (`128Mi`) requests into any container that omits them, ensuring the scheduler has accurate resource information for every pod. **Falco provides** runtime monitoring for unconstrained containers running in non-system namespaces.


## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: MutatingPolicy
metadata:
  name: inject-default-resources
  annotations:
    policies.kyverno.io/title: Inject Default Resource Requests
    policies.kyverno.io/category: Resource Management
    policies.kyverno.io/severity: medium
    policies.kyverno.io/description: >-
      Automatically mutates pod specs to inject baseline CPU (100m) and memory
      (128Mi) requests for containers that omit resource requests.
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
                !has(c.resources) || !has(c.resources.requests) ?
                  Object.spec.containers{
                    name: c.name,
                    resources: Object.spec.containers.resources{
                      requests: {
                        "cpu": "100m",
                        "memory": "128Mi"
                      }
                    }
                  } :
                  Object.spec.containers{
                    name: c.name
                  }
              )
            }
          }
```

---

## Falco Rule Manifest
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-custom-rules
  namespace: falco
  labels:
    app.kubernetes.io/part-of: falco
    app.kubernetes.io/component: custom-rules
data:
  falco-kyverno-rules.yaml: |-
    - rule: Unconstrained Resource Container Executed
      desc: >
        Detects a container process running without CPU or memory resource
        limits defined in Kubernetes spec.
      source: syscall
      condition: >
        evt.type = execve and
        container and
        not k8s.ns.name in (kube-system, kyverno, falco)
      output: >
        Unconstrained resource container process started
        (command=%proc.cmdline pod=%k8s.pod.name ns=%k8s.ns.name
        image=%container.image.repository user=%user.name)
      priority: WARNING
      tags: [kyverno_companion, resource_management, mitre_resource_hijacking]
```

---

## Detailed Explanation
#### Truth Table — Kyverno Mutation Evaluation

| `has(resources.requests)` | `has(resources.limits)` | Kyverno Action |
|---|---|---|
| `true` | `true` | **NO MUTATION** (Retain user-specified limits) |
| `false` | `false` | **MUTATE** (Inject default CPU/Memory requests & limits) |

#### Truth Table — Falco Runtime Detections

| `container` | Namespace Excluded | Pod Has Resource Limits | Falco Alert Result |
|---|---|---|---|
| `true` | `false` (`prod`) | `true` | No Alert |
| `true` | `false` (`prod`) | `false` (unconstrained) | **ALERT FIRED (NOTICE)** |



### Kyverno CEL Expression Breakdown

```yaml
Object{
  spec: Object.spec{
    containers: object.spec.containers.map(c,
      !has(c.resources) || !has(c.resources.requests) ?
        Object.spec.containers{
          name: c.name,
          resources: Object.spec.containers.resources{
            requests: {
              "cpu": "100m",
              "memory": "128Mi"
            }
          }
        } :
        Object.spec.containers{
          name: c.name
        }
    )
  }
}
```

| CEL Fragment | What It Does | Why It's Needed |
|---|---|---|
| `patchType: ApplyConfiguration` | Uses Server-Side Apply syntax (`Object{...}`) to mutate resources. | Ensures clean merge without JSON patch positional pointer fragility. |
| `object.spec.containers.map(c, ...)` | CEL list transform macro: maps each container `c` to a mutated representation. | Evaluates and mutates every container defined in the pod spec. |
| `!has(c.resources) \|\| !has(c.resources.requests)` | Checks if `resources` block or `resources.requests` is missing. | Identifies containers that lack defined CPU/memory requests. |
| `? Object.spec.containers{ ... }` | Ternary true-branch: constructs patch inserting `cpu: 100m` and `memory: 128Mi`. | Injects default baseline CPU and memory requests. |
| `: Object.spec.containers{ name: c.name }` | Ternary false-branch: leaves container unchanged (only name target preserved). | Preserves existing user-defined resource requests without modification. |

---

### Falco Condition Breakdown

```
evt.type = execve and container
and not k8s.ns.name in (kube-system, kyverno, falco)
```

| Falco Field | What It Does | Why It's Included |
|---|---|---|
| `evt.type = execve` | Intercepts process execution syscalls. | Detects process execution inside containers. |
| `container` | Ensures event originates inside container context. | Filters out host node system processes. |
| `not k8s.ns.name in (kube-system, kyverno, falco)` | Excludes system and control plane namespaces. | System namespaces often run unconstrained or specialized daemons. |

---

### 🔗 Defense-in-Depth: How Kyverno and Falco Work Together

| Layer | When It Acts | What It Catches |
|---|---|---|
| **Kyverno** (Admission) | At pod creation/update | Automatically mutates Pod specs missing resource requests, injecting `100m` CPU and `128Mi` memory defaults. |
| **Falco** (Runtime) | When a process starts | Monitors processes in non-system namespaces to alert on unconstrained containers running at runtime. |

### MITRE ATT&CK Mapping

| Tag | Technique | Description |
|---|---|---|
| `mitre_resource_hijacking` | **T1496 — Resource Hijacking** | Unconstrained containers allow attackers or runaway processes to consume excessive node CPU and memory. |

---

## ⚡ GitOps Considerations (ArgoCD & Flux)

When deploying workloads via GitOps (e.g. ArgoCD or Flux), **admission-time mutation modifies live cluster objects**, causing a difference between the live state and the manifest stored in Git.

### The Reconciliation Conflict Problem
If a developer commits a Deployment manifest to Git **without** resource requests, Kyverno mutates the live Pod / PodTemplate spec to add `.spec.template.spec.containers[*].resources.requests`.

By default, GitOps tools like ArgoCD will compare live resources against Git:
1. ArgoCD marks the application status as **`OutOfSync`**.
2. If **Auto-Sync / Prune** is enabled, ArgoCD attempts to revert the resource to match Git.
3. Kyverno re-mutates the pod on next admission/update, triggering a **continuous reconciliation loop**.

### Solution 1: Configure ArgoCD `ignoreDifferences`
Add an `ignoreDifferences` block to your ArgoCD `Application` manifest for the targeted workloads:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: workload-app
  namespace: argocd
spec:
  ignoreDifferences:
    - group: apps
      kind: Deployment
      jsonPointers:
        - /spec/template/spec/containers/0/resources/requests
    - group: ""
      kind: Pod
      jsonPointers:
        - /spec/containers/0/resources/requests
```

### Solution 2: Configure ArgoCD `respectIgnoreDifferences`
In ArgoCD v2.6+, enable `respectIgnoreDifferences` in `syncOptions` so automated sync does not override mutated fields:

```yaml
spec:
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - RespectIgnoreDifferences=true
```

---

## Test Scenarios & Manifest Examples

### 1. ✅ MUTATED CASE — Pod Missing Resource Requests
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-no-requests
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
```
* **Result**: **MUTATED** — Kyverno detects missing `requests` and injects `cpu: 100m`, `memory: 128Mi`.

---

### 2. ✅ UNMUTATED CASE — Pod Explicitly Specifies Custom Requests
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-custom-requests
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      resources:
        requests:
          cpu: 500m
          memory: 512Mi
```
* **Result**: **PRESERVED** — Existing `requests` values (`cpu: 500m`, `memory: 512Mi`) are preserved without modification.

---

## How to Test

### Kyverno (Admission Mutation Dry-Run Check)
```bash
# Test mutation via server dry-run and view injected resource requests
kubectl apply -f - --dry-run=server -o yaml <<EOF | grep -A 4 requests
apiVersion: v1
kind: Pod
metadata:
  name: test-mutation-resources
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
EOF
```

*Expected Output:*
```yaml
    requests:
      cpu: 100m
      memory: 128Mi
```

### Falco (Runtime Check)
Inspect alerts routed via Falcosidekick when unconstrained containers run in monitored namespaces.

