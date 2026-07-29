# Require Resource Limits

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Ensures CPU and Memory values are defined under resources/limits. |
| **Falco Detection** | Alerts when resource benchmarking tools like `stress`, `stress-ng`, or `yes` are spawned. |

## Description
Enforces defined resource quotas (CPU/Memory) on containers to prevent noisy-neighbor scenarios. Detects execution of benchmarking/abuse tools at runtime.

### 🛡️ Problem Statement — What Are We Preventing?

Without CPU and memory limits, a single container can consume all available resources on a node, starving co-located pods and destabilizing the entire cluster. This creates critical availability and security risks:

* **Resource Exhaustion Attacks (MITRE ATT&CK: T1499.004)**: An attacker who gains code execution inside an unlimited container can run fork bombs (`:(){ :|:& };:`), CPU stress tools (`stress-ng`), or memory allocation loops to deliberately exhaust node resources. Without limits, the Linux kernel cannot constrain the container, and the attack impacts every other pod on the node.
* **Noisy Neighbor Problem**: In multi-tenant clusters, a single team's runaway workload (memory leak, infinite loop, unoptimized query) can consume all node CPU or memory, causing latency spikes, OOM kills, and restarts for pods belonging to other teams — even though those pods are functioning correctly.
* **Node-Level OOM Kills**: Without memory limits, the Linux kernel's OOM killer selects victims based on memory consumption patterns rather than cgroup boundaries. It may kill critical system pods (`kubelet`, `kube-proxy`, `CNI agents`) instead of the offending unlimited container, causing the entire node to become unresponsive.
* **Cloud Cost Explosion**: Unlimited containers that consume excessive resources trigger cluster autoscaler scale-ups, provisioning expensive new nodes to handle artificial demand. Without limits, there's no ceiling on per-pod resource consumption, making cloud costs unpredictable.
* **Cryptocurrency Mining Enabler**: Crypto miners are specifically designed to consume 100% of available CPU. Without CPU limits, a miner deployed in an unlimited container can consume the entire node's compute capacity, maximizing the attacker's mining output at the organization's expense.

**Kyverno prevents this** by validating that every container defines explicit `resources.limits.cpu` and `resources.limits.memory` values, ensuring the Linux kernel's cgroup subsystem enforces hard boundaries on resource consumption. **Falco detects** the execution of known resource abuse tools (`stress`, `stress-ng`, `yes`, `dd`) inside containers, alerting on potential resource exhaustion attacks.


## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: require-resource-limits
  annotations:
    policies.kyverno.io/title: Require Resource Limits
    policies.kyverno.io/category: Best Practices
    policies.kyverno.io/severity: medium
    policies.kyverno.io/description: >-
      All containers must define CPU and memory limits to prevent resource
      exhaustion on shared nodes.
  labels:
    app.kubernetes.io/part-of: kyverno-falco-policies
spec:
  validationActions:
    - Deny
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: [CREATE, UPDATE]
        resources: [pods]
  validations:
    - message: "CPU and memory limits are required for all containers."
      expression: >-
        object.spec.containers.all(c,
          has(c.resources) &&
          has(c.resources.limits) &&
          has(c.resources.limits.cpu) &&
          has(c.resources.limits.memory)
        )
```

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
    - rule: Container Resource Exhaustion Behavior
      desc: >
        Detects a container process consuming excessive resources,
        potentially indicating a fork bomb or resource exhaustion attack.
      source: syscall
      condition: >
        evt.type in (execve, execveat) and evt.failed = false and container
        and proc.name in (stress, stress-ng, yes, dd)
        and not k8s.ns.name in (kube-system)
      output: >
        Resource exhaustion tool detected (command=%proc.cmdline
        pod=%k8s.pod.name ns=%k8s.ns.name image=%container.image.repository)
      priority: WARNING
      tags: [kyverno_companion, resource_abuse, mitre_impact]
```

## Detailed Explanation
### Kyverno Policy Manifest Explanation
The policy prevents container resource starvation:
- **`cpu: "?*"` and `memory: "?*"`**: Enforces that both resource limit keys must be set with at least one character, ensuring limits are configured.

### Falco Rule Manifest Explanation
The companion Falco rule detects compute stress tools running inside containers:
- **`proc.name in (stress, stress-ng, yes, dd)`**: Listens for process execution of known benchmarking or disk write utilities.
- **`not k8s.ns.name in (kube-system)`**: Exempts system namespaces to allow standard cluster-level benchmarking.

## How to Test
### Kyverno (Admission Check)
Try to create a pod without specifying resource limits (should be blocked):
```bash
kubectl run test-no-limits --image=nginx --restart=Never
```

### Falco (Runtime Check)
1. Launch a container executing the `yes` tool:
```bash
kubectl run test-exhaustion --image=alpine --restart=Never -it -- yes > /dev/null
```
2. Verify Falco logs warning alert: `Container Resource Exhaustion Behavior`.
3. Clean up:
```bash
kubectl delete pod test-exhaustion
```
