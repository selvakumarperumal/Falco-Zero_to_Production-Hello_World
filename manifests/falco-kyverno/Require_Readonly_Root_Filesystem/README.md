# Require Read-Only Root Filesystem

| Property | Value |
|---|---|
| **Type** | Kyverno (Validation) + Falco (Detection) |
| **Kyverno Prevention** | Validates `readOnlyRootFilesystem: true` under container securityContext. |
| **Falco Detection** | Tracks open/write syscalls targeting root directories (excluding exceptions like `/tmp`). |

## Description
Enforces setting the root filesystem as read-only, restricting writable storage to ephemeral/persistent volumes. Detects write attempts to unauthorized root directory structures.

## Kyverno Policy Manifest
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-readonly-rootfs
  annotations:
    policies.kyverno.io/title: Require Read-Only Root Filesystem
    policies.kyverno.io/category: Pod Security Standards (Restricted)
    policies.kyverno.io/severity: medium
    policies.kyverno.io/description: >-
      Containers must use a read-only root filesystem. Any writable
      paths should be explicitly defined as volume mounts.
  labels:
    app.kubernetes.io/part-of: kyverno-falco-policies
spec:
  validationFailureAction: Audit
  rules:
    - name: require-readonly-rootfs
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: "Root filesystem must be read-only. Set securityContext.readOnlyRootFilesystem to true."
        pattern:
          spec:
            containers:
              - securityContext:
                  readOnlyRootFilesystem: true
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
    - rule: Write to Container Root Filesystem
      desc: >
        Detects file writes to the container root filesystem, excluding
        known-safe paths like /tmp and /proc.
      condition: >
        evt.type in (open, openat, openat2) and evt.dir = <
        and container
        and evt.is_open_write = true
        and not fd.name startswith "/tmp"
        and not fd.name startswith "/proc"
        and not fd.name startswith "/dev"
        and not fd.name startswith "/sys"
        and fd.name != ""
        and not k8s.ns.name in (kube-system, kyverno)
      output: >
        File written to container root fs (file=%fd.name command=%proc.cmdline
        pod=%k8s.pod.name ns=%k8s.ns.name)
      priority: WARNING
      tags: [kyverno_companion, rootfs_write, mitre_persistence]
```

## Detailed Explanation
### Kyverno Policy Manifest Explanation
The policy enforces read-only root filesystems:
- **`validationFailureAction: Audit`**: Analyzes and flags missing settings.
- **`readOnlyRootFilesystem: true`**: Enforces container security contexts to block disk writes to the root filesystem layer.

### Falco Rule Manifest Explanation
The companion Falco rule detects write operations at runtime:
- **`evt.is_open_write = true`**: Triggers only when a file open syscall requests write access.
- **`not fd.name startswith "/tmp"` or `/proc` or `/dev` or `/sys`**: Excludes directories that require writing or virtual filesystems. Write events in any other filesystem path trigger a `WARNING` level alert.

## How to Test
### Kyverno (Admission Check)
Create a pod without setting readOnlyRootFilesystem to true (triggers Audit or Enforce):
```bash
kubectl run test-writable-fs --image=nginx --restart=Never
```

### Falco (Runtime Check)
1. Run a pod and try to write directly to a root directory:
```bash
kubectl run test-root-write --image=alpine --restart=Never -it -- sh -c "echo 'bad' > /root/compromised.txt"
```
2. Check Falco alerts for: `Write to Container Root Filesystem`.
3. Clean up:
```bash
kubectl delete pod test-root-write
```
