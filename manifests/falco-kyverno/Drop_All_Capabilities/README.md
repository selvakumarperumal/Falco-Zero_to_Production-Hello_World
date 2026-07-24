# Drop All Capabilities

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Ensures `ALL` is listed in the dropped capabilities array of container definitions. |
| **Falco Detection** | Monitors syscalls indicating dangerous capability manipulation. |

## Description
Enforces the best practice of dropping all default Linux capabilities on containers. Detects usage of tools interacting with namespaces/capabilities (e.g. `unshare`, `nsenter`, `capsh`) at runtime.

## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: drop-all-capabilities
  annotations:
    policies.kyverno.io/title: Drop All Capabilities
    policies.kyverno.io/category: Pod Security Standards (Restricted)
    policies.kyverno.io/severity: medium
    policies.kyverno.io/description: >-
      Containers must drop ALL Linux capabilities. Only explicitly needed
      capabilities should be added back.
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
    - message: "Containers must drop ALL capabilities."
      expression: >-
        object.spec.containers.all(c,
          has(c.securityContext) &&
          has(c.securityContext.capabilities) &&
          has(c.securityContext.capabilities.drop) &&
          c.securityContext.capabilities.drop.exists(x, x == 'ALL')
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
    - rule: Dangerous Capability Used at Runtime
      desc: >

      source: syscall
        Detects a process attempting to use dangerous Linux capabilities
        such as SYS_ADMIN, SYS_PTRACE, or NET_RAW.
      condition: >
        spawned_process and container
        and (proc.name = "nsenter" or proc.name = "unshare"
          or proc.cmdline contains "capsh"
          or proc.cmdline contains "--cap-add")
      output: >
        Dangerous capability usage detected (command=%proc.cmdline
        user=%user.name pod=%k8s.pod.name ns=%k8s.ns.name)
      priority: WARNING
      tags: [kyverno_companion, capabilities, mitre_privilege_escalation]
```

## Detailed Explanation
### Kyverno Policy Manifest Explanation
The policy locks down OS-level capabilities:
- **`validations[].expression`**: CEL expression evaluated against `object.spec` containers.
- **`validations[].expression`**: CEL validation rules enforcing compliance.

### Falco Rule Manifest Explanation
The runtime rule monitors execution of kernel manipulation commands:
- **`proc.name in (nsenter, unshare)` or `proc.cmdline contains "capsh"`**: Detects processes targeting kernel namespaces or capability configuration. If an attacker gains command access inside a container and tries to execute these binaries, Falco flags it as a `WARNING`.

## How to Test
### Kyverno (Admission Check)
Try to deploy a pod without specifying dropped capabilities (should be blocked):
```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-capabilities
spec:
  containers:
  - name: nginx
    image: nginx
EOF
```

### Falco (Runtime Check)
1. Run a shell and invoke a namespace manipulation utility:
```bash
kubectl run test-cap-use --image=alpine --restart=Never -it -- unshare -h
```
2. Verify Falco triggers alert: `Dangerous Capability Used at Runtime`.
3. Clean up:
```bash
kubectl delete pod test-cap-use
```
