# Mutate Image Pull Policy to Always

| Property | Value |
|---|---|
| **Type** | Kyverno (Mutation) |
| **Kyverno Prevention** | Mutates pod specifications to change container image pull policies conditional on `:latest` image names. |
| **Falco Detection** | N/A (Admission mutation). |

## Description
Ensures any container specifying the `:latest` tag is updated to use `imagePullPolicy: Always` at admission time. This guarantees that stale cached images are not accidentally reused.

## How to Test
1. Submit a dry-run server request for a pod using `:latest` without specifying the pull policy:
```bash
kubectl run test-mutate-pull --image=nginx:latest --dry-run=server -o yaml | grep imagePullPolicy
```
2. Confirm the output includes `imagePullPolicy: Always` mutated by Kyverno.
