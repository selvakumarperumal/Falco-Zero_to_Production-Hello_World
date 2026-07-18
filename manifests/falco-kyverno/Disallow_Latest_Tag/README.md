# Disallow Latest Tag

| Property | Value |
|---|---|
| **Type** | Kyverno (Validation) + Falco (Detection) |
| **Kyverno Prevention** | Validates that container images do not end in `:latest` and explicitly contain a colon. |
| **Falco Detection** | Detects container start events where the image repository tag is `latest` or blank. |

## Description
Ensures all container deployments use specific version tags instead of the mutable `:latest` tag to ensure reproducibility and tracking. Detects containers starting with `:latest` tag at runtime.

## How to Test
### Kyverno (Admission Check)
Attempt to deploy a pod using the latest tag (should be blocked):
```bash
kubectl run test-latest --image=nginx:latest --restart=Never
```

### Falco (Runtime Check)
Start a container running `:latest` (e.g. during an audit rollout) and inspect Falco alerts for: `Container Running with Latest Tag`.
