# Require Read-Only Root Filesystem

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Validates `readOnlyRootFilesystem: true` under container securityContext. |
| **Falco Detection** | Tracks open/write syscalls targeting root directories (excluding exceptions like `/tmp`). |

## Description
Enforces setting the root filesystem as read-only, restricting writable storage to ephemeral/persistent volumes. Detects write attempts to unauthorized root directory structures.

### 🛡️ Problem Statement — What Are We Preventing?

By default, containers have a writable root filesystem, meaning any process inside the container can create, modify, or delete files anywhere in the filesystem. This writable surface is a critical enabler for multiple attack techniques:

* **Malware Persistence (MITRE ATT&CK: T1546)**: An attacker who gains code execution inside a container can write malicious binaries, scripts, or backdoors directly to the filesystem. These persist across process restarts within the same container lifecycle, allowing the attacker to maintain access even if their initial exploit vector is patched.
* **Web Shell Installation**: One of the most common post-exploitation actions is writing a web shell (e.g., a PHP or JSP file) to the application's web root. With a writable filesystem, attackers can drop web shells that provide persistent remote access via HTTP — completely bypassing network-level security controls.
* **Binary Tampering**: Attackers can replace legitimate binaries (e.g., `/usr/bin/curl`, `/usr/bin/wget`) with trojanized versions that exfiltrate data or maintain command-and-control channels. With a read-only filesystem, any attempt to modify system binaries fails immediately.
* **Configuration Poisoning**: Critical configuration files (`/etc/resolv.conf`, `/etc/hosts`, application config files) can be modified by an attacker to redirect DNS queries, intercept traffic, or change application behavior — enabling man-in-the-middle attacks from within the container.
* **Container Immutability Principle**: The principle of immutable infrastructure requires that containers be identical to their image at all times. A writable filesystem violates this principle, making it impossible to guarantee that what's running in production matches what was built, tested, and scanned in CI/CD.

**Kyverno prevents this** by validating that every container sets `readOnlyRootFilesystem: true` in its `securityContext`, forcing developers to explicitly declare writable paths as volume mounts (e.g., `emptyDir` for `/tmp`). **Falco detects** runtime write attempts to the container root filesystem, alerting on potential malware installation or configuration tampering.


## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
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
  validationActions:
    - Audit
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: [CREATE, UPDATE]
        resources: [pods]
  validations:
    - message: "Root filesystem must be read-only. Set securityContext.readOnlyRootFilesystem to true."
      expression: >-
        object.spec.containers.all(c,
          has(c.securityContext) &&
          has(c.securityContext.readOnlyRootFilesystem) &&
          c.securityContext.readOnlyRootFilesystem == true
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
    - rule: Write to Container Root Filesystem
      desc: >
        Detects file writes to the container root filesystem, excluding
        known-safe paths like /tmp and /proc.
      source: syscall
      condition: >
        evt.type in (open, openat, openat2)
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
- **`validationActions`**: Set to `Deny` to block non-compliant requests at admission time.
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
