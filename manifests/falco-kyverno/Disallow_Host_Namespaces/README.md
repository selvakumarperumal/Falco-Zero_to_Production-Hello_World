# Disallow Host Namespaces

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Enforces `hostPID: false`, `hostIPC: false`, and `hostNetwork: false` on pod specifications. |
| **Falco Detection** | Detects container start events containing flags `CLONE_NEWPID` or `CLONE_NEWNET`. |

## Description
Blocks pods sharing host PID, IPC, or Network namespaces (which breaks node isolation). Detects namespace clone flags during container startup at runtime.

## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
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
  validationActions:
    - Deny
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: [CREATE, UPDATE]
        resources: [pods]
  validations:
    - message: "Host PID, IPC, and network namespaces are not allowed."
      expression: >-
        !(has(object.spec.hostPID) && object.spec.hostPID == true) &&
        !(has(object.spec.hostIPC) && object.spec.hostIPC == true) &&
        !(has(object.spec.hostNetwork) && object.spec.hostNetwork == true)
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
    - rule: Container Using Host Namespace
      desc: Detects a container sharing host PID or network namespaces.
      source: syscall
      condition: >
        evt.type = execve and
        container and
        (evt.arg.flags contains "CLONE_NEWPID" or evt.arg.flags contains "CLONE_NEWNET")
      output: >
        Container using host namespace (user=%user.name pod=%k8s.pod.name
        ns=%k8s.ns.name image=%container.image.repository)
      priority: CRITICAL
      tags: [kyverno_companion, host_namespace, mitre_privilege_escalation]
```

## Detailed Explanation
### Kyverno Policy Manifest Explanation
This policy prevents container breakout to the host namespaces:
- **`validationActions`**: Set to `Deny` to block non-compliant requests at admission time.
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
