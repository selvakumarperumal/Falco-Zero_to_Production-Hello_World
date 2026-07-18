# Disallow Privileged Containers

| Property | Value |
|---|---|
| **Type** | Kyverno (Validation) + Falco (Detection) |
| **Kyverno Prevention** | Enforces `privileged: false` on container security contexts. |
| **Falco Detection** | Detects container start events where `container.privileged = true`. |

## Description
Prevents deploying containers with full host root level access (`privileged: true`). Tracks and alerts if a privileged container gets spawned.

## Kyverno Policy Manifest
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
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
  validationFailureAction: Enforce
  rules:
    - name: deny-privileged
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: "Privileged containers are not allowed."
        pattern:
          spec:
            containers:
              - securityContext:
                  privileged: "false"
            =(initContainers):
              - securityContext:
                  privileged: "false"
            =(ephemeralContainers):
              - securityContext:
                  privileged: "false"
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
    - rule: Privileged Container Started
      desc: >
        Detects a container that was started with privileged mode.
        This should never happen if Kyverno is enforcing, so this alert
        means either Kyverno was bypassed or is in Audit mode.
      condition: >
        container_started and container and container.privileged = true
      output: >
        Privileged container started (user=%user.name pod=%k8s.pod.name
        ns=%k8s.ns.name image=%container.image.repository)
      priority: CRITICAL
      tags: [kyverno_companion, privileged, mitre_privilege_escalation]
```

## Detailed Explanation
### Kyverno Policy Manifest Explanation
The Kyverno check enforces a baseline security profile:
- **`validationFailureAction: Enforce`**: Blocks creation of any pod violating the policy.
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
