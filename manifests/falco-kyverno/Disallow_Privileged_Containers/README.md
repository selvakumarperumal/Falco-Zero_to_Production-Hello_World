# Disallow Privileged Containers

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Enforces `privileged: false` on container security contexts. |
| **Falco Detection** | Detects container start events where `container.privileged = true`. |

## Description
Prevents deploying containers with full host root level access (`privileged: true`). Tracks and alerts if a privileged container gets spawned.

## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: disallow-privileged-containers
  annotations:
    policies.kyverno.io/title: Disallow Privileged Containers
    policies.kyverno.io/category: Pod Security Standards (Baseline)
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      Privileged containers have full access to the host. This policy
      ensures that the privileged flag is never set to true.
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
    - message: "Privileged containers are not allowed."
      expression: >-
        !object.spec.containers.exists(c, has(c.securityContext) && has(c.securityContext.privileged) && c.securityContext.privileged == true) &&
        !object.spec.?initContainers.orValue([]).exists(c, has(c.securityContext) && has(c.securityContext.privileged) && c.securityContext.privileged == true) &&
        !object.spec.?ephemeralContainers.orValue([]).exists(c, has(c.securityContext) && has(c.securityContext.privileged) && c.securityContext.privileged == true)
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
    - rule: Privileged Container Started
      desc: Detects a container spawned with host privileged mode enabled.
      source: syscall
      condition: >
        evt.type = execve and
        container and container.privileged = true
      output: >
        Privileged container started (user=%user.name pod=%k8s.pod.name
        ns=%k8s.ns.name image=%container.image.repository)
      priority: CRITICAL
      tags: [kyverno_companion, privileged, mitre_privilege_escalation]
```

## Detailed Explanation
### Kyverno Policy Manifest Explanation
The Kyverno check enforces a baseline security profile:
- **`validationActions`**: Set to `Deny` to block non-compliant requests at admission time.
- **`privileged: "false"`**: Checks container, initContainer, and ephemeralContainer profiles. Rejects any manifest that sets the `privileged` attribute to `true`.

### Falco Rule Manifest Explanation
The runtime rule acts as a core security check:
- **`container_started and container`**: Listens for runtime container initialization.
- **`container.privileged = true`**: Assesses container status from container runtime metadata. If the container was somehow started with privileged flags enabled, Falco triggers a `CRITICAL` alert.

## How to Test
### Kyverno (Admission Check)
Deploy a container with privileged mode (should be blocked):
```bash
kubectl run test-priv --image=nginx --restart=Never --overrides='{"spec":{"containers":[{"name":"test-priv","image":"nginx","securityContext":{"privileged":true}}]}}'
```

### Falco (Runtime Check)
If admission control is bypassed or in audit mode, verify Falco triggers: `Privileged Container Started`.
