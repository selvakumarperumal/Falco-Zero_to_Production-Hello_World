# Disallow Host Namespaces

| Property | Value |
|---|---|
| **Type** | Kyverno (Validation) + Falco (Detection) |
| **Kyverno Prevention** | Enforces `hostPID: false`, `hostIPC: false`, and `hostNetwork: false` on pod specifications. |
| **Falco Detection** | Detects container start events containing flags `CLONE_NEWPID` or `CLONE_NEWNET`. |

## Description
Blocks pods sharing host PID, IPC, or Network namespaces (which breaks node isolation). Detects namespace clone flags during container startup at runtime.

## Kyverno Policy Manifest
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-host-namespaces
  annotations:
    policies.kyverno.io/title: Disallow Host Namespaces
    policies.kyverno.io/category: Pod Security Standards (Baseline)
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      Containers must not share the host PID, IPC, or network namespaces.
  labels:
    app.kubernetes.io/part-of: kyverno-falco-policies
spec:
  validationFailureAction: Enforce
  rules:
    - name: deny-host-namespaces
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: "Host PID, IPC, and network namespaces are not allowed."
        pattern:
          spec:
            =(hostPID): "false"
            =(hostIPC): "false"
            =(hostNetwork): "false"
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
    - rule: Container Using Host Namespace
      desc: >
        Detects a container running with host PID or network namespace.
      condition: >
        container_started and container
        and (container.privileged = true or k8s.pod.name != "")
        and (evt.arg.flags contains "CLONE_NEWPID"
          or evt.arg.flags contains "CLONE_NEWNET")
      output: >
        Container uses host namespace (pod=%k8s.pod.name ns=%k8s.ns.name
        image=%container.image.repository)
      priority: CRITICAL
      tags: [kyverno_companion, host_namespace, mitre_privilege_escalation]
```

## Detailed Explanation
### Kyverno Policy Manifest Explanation
This policy prevents container breakout to the host namespaces:
- **`validationFailureAction: Enforce`**: Blocks non-compliant pods immediately.
- **`=(hostPID): "false"`**, **`=(hostIPC): "false"`**, **`=(hostNetwork): "false"`**: Validates that if these properties exist in the pod spec, they must be set to `false`.

### Falco Rule Manifest Explanation
The Falco check catches namespace sharing at runtime:
- **`container_started and container`**: Triggers when a container is initialized.
- **`evt.arg.flags contains "CLONE_NEWPID"` or `CLONE_NEWNET`**: Inspects clone flags. If a container is started with the host namespace flag set, it means the container is sharing the host namespace, triggering a `CRITICAL` alert.

## How to Test
### Kyverno (Admission Check)
Attempt to deploy a pod with host namespace access enabled (should be blocked):
```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-host-ns
spec:
  hostPID: true
  containers:
  - name: nginx
    image: nginx
EOF
```

### Falco (Runtime Check)
If admission control is bypassed or in audit-only mode, starting a container with host namespaces will fire the alert: `Container Using Host Namespace`.
