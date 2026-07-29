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

## Test Scenarios & Manifest Examples

### 1. ✅ PASS Case — Read-Only Root Filesystem Enabled
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-readonly-fs
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        readOnlyRootFilesystem: true
```
* **Result**: **PASS** — `c.securityContext.readOnlyRootFilesystem == true` evaluates `true`.

---

### 2. ✅ REALISTIC PASS Case — Read-Only Root FS with Writable `/tmp` Volume Mount
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-readonly-with-tmp
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        readOnlyRootFilesystem: true
      volumeMounts:
        - mountPath: /tmp
          name: tmp-volume
  volumes:
    - name: tmp-volume
      emptyDir: {}
```
* **Result**: **PASS** — Root filesystem remains read-only while temporary file writes are scoped to the `emptyDir` volume.

---

### 3. ❌ FAIL Case 1 — `readOnlyRootFilesystem: false`
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-writable-fs
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        readOnlyRootFilesystem: false
```
* **Result**: **FAIL** — `c.securityContext.readOnlyRootFilesystem == true` evaluates `false`.

---

### 4. ❌ FAIL Case 2 — `readOnlyRootFilesystem` Omitted
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-omitted-readonly
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
```
* **Result**: **FAIL** — `has(c.securityContext.readOnlyRootFilesystem)` evaluates `false`.

---

## How to Test

### Kyverno (Admission Control Dry-Run Check)
```bash
# 1. Test PASS case (readOnlyRootFilesystem: true)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-readonly
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        readOnlyRootFilesystem: true
EOF

# 2. Test FAIL case (omitted readOnlyRootFilesystem)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-writable
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
EOF
```

### Falco (Runtime Write Check)
1. Run a pod and attempt writing to a non-exempt root directory:
```bash
kubectl run test-root-write --image=alpine --restart=Never -it -- sh -c "echo 'bad' > /root/compromised.txt"
```
2. Verify Falco logs warning alert: `Write to Container Root Filesystem`.
3. Clean up:
```bash
kubectl delete pod test-root-write --ignore-not-found
```

