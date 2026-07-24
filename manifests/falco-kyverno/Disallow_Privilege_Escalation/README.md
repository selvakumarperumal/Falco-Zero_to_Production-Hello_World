# Disallow Privilege Escalation

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Enforces `allowPrivilegeEscalation: false` on all containers. |
| **Falco Detection** | Detects spawned processes of setuid/setgid binaries like `sudo`, `su`, `passwd` at runtime. |

## Description
Ensures that `allowPrivilegeEscalation` is configured as false (preventing sub-processes from gaining more privileges than their parent). Detects execution of setuid/setgid binaries inside containers.

## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: disallow-privilege-escalation
  annotations:
    policies.kyverno.io/title: Disallow Privilege Escalation
    policies.kyverno.io/category: Pod Security Standards (Restricted)
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      Containers must not allow privilege escalation via setuid/setgid binaries.
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
    - message: "Privilege escalation is not allowed. Set allowPrivilegeEscalation to false."
      expression: >-
        object.spec.containers.all(c,
          has(c.securityContext) &&
          has(c.securityContext.allowPrivilegeEscalation) &&
          c.securityContext.allowPrivilegeEscalation == false
        ) &&
        object.spec.?initContainers.orValue([]).all(c,
          has(c.securityContext) &&
          has(c.securityContext.allowPrivilegeEscalation) &&
          c.securityContext.allowPrivilegeEscalation == false
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
    - rule: Setuid or Setgid Binary Executed in Container
      desc: >

      source: syscall
        Detects execution of setuid/setgid binaries inside a container,
        which can be used for privilege escalation.
      condition: >
        spawned_process and container
        and (proc.name in (sudo, su, newgrp, chsh, chfn, passwd)
          or proc.name = "pkexec")
        and not k8s.ns.name in (kube-system)
      output: >
        Setuid/setgid binary executed (command=%proc.cmdline user=%user.name
        pod=%k8s.pod.name ns=%k8s.ns.name image=%container.image.repository)
      priority: ERROR
      tags: [kyverno_companion, privilege_escalation, mitre_privilege_escalation]
```

## Detailed Explanation
### Kyverno Policy Manifest Explanation
The policy limits process permissions escalation:
- **`spec.containers.securityContext.allowPrivilegeEscalation: false`**: Validates that all containers must have this attribute explicitly set to `false`.
- **`=(initContainers)`**: Ensures the rule is also applied to initialization containers if they exist.

### Falco Rule Manifest Explanation
The runtime check detects usage of privilege escalation mechanisms:
- **`proc.name in (sudo, su, newgrp, chsh, chfn, passwd, pkexec)`**: Checks if the spawned process matches known setuid/setgid binary commands.
- **`not k8s.ns.name in (kube-system)`**: Ignores system tasks operating inside `kube-system` to limit alerts to application namespaces.

## How to Test
### Kyverno (Admission Check)
Deploy a pod explicitly enabling privilege escalation (should be blocked):
```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-priv-esc
spec:
  containers:
  - name: nginx
    image: nginx
    securityContext:
      allowPrivilegeEscalation: true
EOF
```

### Falco (Runtime Check)
1. Run a container and try executing a setuid/setgid binary such as `su`:
```bash
kubectl run test-su --image=alpine --restart=Never -it -- su
```
2. Check Falco alerts for: `Setuid or Setgid Binary Executed in Container`.
3. Clean up:
```bash
kubectl delete pod test-su
```
