# Disallow Privileged Containers

| Property | Value |
|---|---|
| **Type** | Kyverno (Validation) + Falco (Detection) |
| **Kyverno Prevention** | Enforces `privileged: false` on container security contexts. |
| **Falco Detection** | Detects container start events where `container.privileged = true`. |

## Description
Prevents deploying containers with full host root level access (`privileged: true`). Tracks and alerts if a privileged container gets spawned.

## How to Test
### Kyverno (Admission Check)
Deploy a container with privileged mode (should be blocked):
```bash
kubectl run test-priv --image=nginx --restart=Never --overrides='{"spec":{"containers":[{"name":"test-priv","image":"nginx","securityContext":{"privileged":true}}]}}'
```

### Falco (Runtime Check)
If admission control is bypassed or in audit mode, verify Falco triggers: `Privileged Container Started`.
