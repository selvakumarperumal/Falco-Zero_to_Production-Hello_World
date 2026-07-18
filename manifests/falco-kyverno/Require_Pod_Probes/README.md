# Require Pod Probes

| Property | Value |
|---|---|
| **Type** | Kyverno (Validation) + Falco (Detection) |
| **Kyverno Prevention** | Ensures container spec includes `livenessProbe` and `readinessProbe` blocks. |
| **Falco Detection** | Detects rapid process restarts inside containers exiting within short durations. |

## Description
Enforces configuration of liveness and readiness health probes for app reliability. Detects crash loops (rapid container restarts with exit code) at runtime.

## Kyverno Policy Manifest
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-pod-probes
  annotations:
    policies.kyverno.io/title: Require Pod Probes
    policies.kyverno.io/category: Best Practices
    policies.kyverno.io/severity: medium
    policies.kyverno.io/description: >-
      All containers must define liveness and readiness probes to ensure
      Kubernetes can detect and recover from unhealthy states.
    pod-policies.kyverno.io/autogen-controllers: DaemonSet,Deployment,StatefulSet
  labels:
    app.kubernetes.io/part-of: kyverno-falco-policies
spec:
  validationFailureAction: Audit
  rules:
    - name: validate-probes
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: "Liveness and readiness probes are required for all containers."
        pattern:
          spec:
            containers:
              - livenessProbe: "?*"
                readinessProbe: "?*"
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
  # -------------------------------------------------------------------------
  # Original hello-world rules (preserved from existing ConfigMap)
  # -------------------------------------------------------------------------
  hello-world-rules.yaml: |-
    - rule: Container Process Crash Loop Detected
      desc: >
        Detects repeated process crashes in a container, which may
        indicate an unhealthy application bypassing health probe checks.
      condition: >
        spawned_process and container
        and proc.name in (sh, bash)
        and proc.cmdline contains "exit"
        and proc.duration <= 5000000000
      output: >
        Rapid process restart detected (command=%proc.cmdline
        pod=%k8s.pod.name ns=%k8s.ns.name)
      priority: NOTICE
      tags: [kyverno_companion, health, reliability]
```

## Detailed Explanation
### Kyverno Policy Manifest Explanation
The policy enforces application health checks:
- **`validationFailureAction: Audit`**: Flags missing probes in audit reports without blocking deployment.
- **`pod-policies.kyverno.io/autogen-controllers`**: Automatically generates matching policies for container controllers like Deployment, StatefulSet, and DaemonSet.
- **`livenessProbe: "?*"` and `readinessProbe: "?*"`**: Requires both probe keys to be populated.

### Falco Rule Manifest Explanation
The companion Falco rule detects unstable application crash loops:
- **`proc.name in (sh, bash) and proc.cmdline contains "exit"`**: Identifies shell-based termination execution.
- **`proc.duration <= 5000000000`**: Tracks the process lifespan (5 billion nanoseconds = 5 seconds). If shell processes execute and exit within 5 seconds, it flags potential crash loop behavior.

## How to Test
### Kyverno (Admission Check)
Try to deploy a pod without defining health probes (depending on mode, it registers an audit report or gets blocked):
```bash
kubectl run test-no-probes --image=nginx --restart=Never
```

### Falco (Runtime Check)
1. Run a container that exits/crashes immediately:
```bash
kubectl run test-crashing --image=alpine --restart=Never -- sh -c "exit 1"
```
2. Verify Falco triggers alert: `Container Process Crash Loop Detected`.
3. Clean up:
```bash
kubectl delete pod test-crashing
```
