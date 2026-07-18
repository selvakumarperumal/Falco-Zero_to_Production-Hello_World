# Restrict Image Registries

| Property | Value |
|---|---|
| **Type** | Kyverno (Validation) + Falco (Detection) |
| **Kyverno Prevention** | Validates image prefix patterns against lists containing ECR, ghcr, and gcr. |
| **Falco Detection** | Alerts when a container starts using an image not explicitly matched to trusted hosts. |

## Description
Limits container deployments to approved corporate registries. Detects containers executing code using images sourced from unapproved domains.

## How to Test
### Kyverno (Admission Check)
Try to run a container from an unapproved registry (should be blocked):
```bash
kubectl run test-untrusted-reg --image=quay.io/sysdig/falco --restart=Never
```

### Falco (Runtime Check)
Spawn a container from an untrusted registry (in audit mode/unblocked namespace) and check for: `Container from Untrusted Registry`.
