# Require Run As Non Root

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Enforces `runAsNonRoot: true` in the container securityContext. |
| **Falco Detection** | Alerts when a spawned process is executed with UID 0 (root) inside namespaces. |

## Description
Ensures containers run as non-root users (UID != 0). Monitors and alerts on root UID execution at runtime.

## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: require-run-as-non-root
  annotations:
    policies.kyverno.io/title: Require runAsNonRoot
    policies.kyverno.io/category: Pod Security Standards (Restricted)
    policies.kyverno.io/severity: medium
    policies.kyverno.io/description: >-
      Containers must set runAsNonRoot to true to prevent running as UID 0.
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
    - message: "Containers must not run as root. Set securityContext.runAsNonRoot to true."
      expression: >-
        (has(object.spec.securityContext) && has(object.spec.securityContext.runAsNonRoot) && object.spec.securityContext.runAsNonRoot == true) ||
        object.spec.containers.all(c, has(c.securityContext) && has(c.securityContext.runAsNonRoot) && c.securityContext.runAsNonRoot == true)
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
    - rule: Container Running as Root User
      desc: Detects a process spawned with UID 0 (root) inside an application container.
      source: syscall
      condition: >
        evt.type = execve and
        container and user.uid = 0 and
        not k8s.ns.name in (kube-system, kyverno, falco)
      output: >
        Process running as root in container (user=%user.name uid=%user.uid
        command=%proc.cmdline pod=%k8s.pod.name ns=%k8s.ns.name)
      priority: WARNING
      tags: [kyverno_companion, root_user, mitre_privilege_escalation]
```

## Detailed Explanation
### Kyverno Policy Manifest Explanation
The policy validates the execution context user:
- **`runAsNonRoot: true`**: Enforces that Kubernetes must check the image configuration (or securityContext) to verify it does not run as user UID 0.

### Falco Rule Manifest Explanation
The companion Falco rule monitors the active process UID at runtime:
- **`user.uid = 0`**: Triggers if any process spawns with UID 0 (root).
- **`not k8s.ns.name in (kube-system, kyverno)`**: Ignores cluster system processes which often require root privileges.

## How to Test
### Kyverno (Admission Check)
Attempt to deploy a standard root-default container (should be blocked):
```bash
kubectl run test-root-deploy --image=nginx --restart=Never
```

### Falco (Runtime Check)
1. Spawn a shell running as root:
```bash
kubectl run test-root-check --image=alpine --restart=Never -it -- id
```
2. Verify Falco fires: `Container Running as Root User`.
3. Clean up:
```bash
kubectl delete pod test-root-check
```
