# Inject Default Resource Requests & Limits

| Property | Value |
|---|---|
| **Type** | Kyverno (MutatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Automatically mutates pod definitions at admission to inject default CPU (`100m`) and Memory (`128Mi`) requests if omitted. |
| **Falco Detection** | Monitors process execution inside containers running in non-system namespaces to flag unconstrained pods. |

## Description
Enforces cloud-native resource management best practices. When developers submit Pod manifests without specifying CPU or memory requests, Kyverno mutates the incoming object at admission time to inject default baseline requests (`100m` CPU, `128Mi` Memory). This prevents unconstrained pods from starving cluster node capacity.

---

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
        evt.type = execve and evt.dir = < and
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

### Kyverno Policy Explanation
The policy uses modern **Kyverno v1.15+ CEL-based `MutatingPolicy`**:
- **`matchConstraints`**: Intercepts Pod creation and update operations.
- **`patchType: ApplyConfiguration`**: Uses Kubernetes CEL object initialization syntax (`Object{spec: Object.spec{...}}`) to merge resource requests safely.
- **CEL Expression**: Maps through each container (`object.spec.containers.map(c, ...)`). If a container lacks `c.resources` or `c.resources.requests`, it dynamically injects `"cpu": "100m"` and `"memory": "128Mi"`.

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

## How to Test

### 1. Kyverno (Admission Mutation Check)
Deploy a pod **without** resource requests:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-mutation-resources
spec:
  containers:
  - name: nginx
    image: nginx
EOF
```

Verify that Kyverno automatically mutated the pod spec to inject baseline resource requests:

```bash
kubectl get pod test-mutation-resources -o yaml | grep -A 4 requests
```

*Expected Output:*
```yaml
    requests:
      cpu: 100m
      memory: 128Mi
```

Clean up test pod:
```bash
kubectl delete pod test-mutation-resources
```

### 2. Falco (Runtime Check)
Inspect alerts routed via Falcosidekick when unconstrained containers run in monitored namespaces.
