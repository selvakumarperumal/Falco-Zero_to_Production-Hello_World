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
#### Truth Table — Kyverno CEL Evaluation

| `has(securityContext)` | `has(readOnlyRootFilesystem)` | `readOnlyRootFilesystem` Value | Policy Decision |
|---|---|---|---|
| `false` | — | — | **FAIL** |
| `true` | `true` | `false` | **FAIL** |
| `true` | `true` | `true` | **PASS** |

#### Truth Table — Falco Runtime Detections

| `container` | `evt.is_open_write` | Target `fd.name` Path | Falco Alert Result |
|---|---|---|---|
| `true` | `true` | `/tmp/cache.txt` (Exempt `/tmp`) | No Alert |
| `true` | `true` | `/etc/config.json` (Root FS) | **ALERT FIRED (ERROR)** |



### Kyverno CEL Expression Breakdown

```
object.spec.containers.all(c,
  has(c.securityContext) &&
  has(c.securityContext.readOnlyRootFilesystem) &&
  c.securityContext.readOnlyRootFilesystem == true
)
```

| CEL Fragment | What It Does | Why It's Needed |
|---|---|---|
| `object.spec.containers.all(c, ...)` | CEL list macro: every container must satisfy the predicate. | All containers must have read-only root filesystems — one writable container is enough for an attacker to persist. |
| `has(c.securityContext)` | Checks if `securityContext` exists on the container. | Guards against null reference when the field is omitted. |
| `has(c.securityContext.readOnlyRootFilesystem)` | Checks if the `readOnlyRootFilesystem` field is explicitly set. | The field defaults to `false` when absent — we require it to be explicitly set to `true`. |
| `c.securityContext.readOnlyRootFilesystem == true` | Validates the actual value is `true`. | When `true`, the container runtime mounts the root filesystem as read-only. Writes are only possible to explicitly mounted volumes (e.g., `emptyDir` for `/tmp`). |

> **Note:** This policy uses `validationActions: [Audit]` (not `Deny`). Many applications write to `/tmp`, `/var/cache`, or logging directories. Start in Audit mode, add `emptyDir` volumes for writable paths, then switch to `Deny`.

#### CEL Evaluation Trace — Container with Read-Only Root FS

```
Step 1: has(c.securityContext) → true
Step 2: has(c.securityContext.readOnlyRootFilesystem) → true
Step 3: c.securityContext.readOnlyRootFilesystem == true → true
Step 4: .all() returns true → ADMITTED
```

---

### Falco Condition Breakdown

```
evt.type in (open, openat, openat2) and container
and evt.is_open_write = true
and not fd.name startswith "/tmp"
and not fd.name startswith "/proc"
and not fd.name startswith "/dev"
and not fd.name startswith "/sys"
and fd.name != ""
and not k8s.ns.name in (kube-system, kyverno)
```

| Falco Field | What It Does | Why It's Included |
|---|---|---|
| `evt.type in (open, openat, openat2)` | Matches file open syscalls. `open` is the legacy call; `openat` and `openat2` are directory-relative variants used by modern applications. | These syscalls are used to open files for reading or writing — by filtering on them, we detect the exact moment a write attempt occurs. |
| `container` | Event originates inside a container. | Host filesystem writes are normal OS operations and irrelevant to this policy. |
| `evt.is_open_write = true` | Falco helper that checks if the open flags include `O_WRONLY` or `O_RDWR`. | Only write operations are security-relevant — reads from the root filesystem are expected behavior. |
| `not fd.name startswith "/tmp"` | Excludes writes to `/tmp`. | `/tmp` is typically mounted as an `emptyDir` volume even on read-only containers. Writes here are expected and safe. |
| `not fd.name startswith "/proc"` / `"/dev"` / `"/sys"` | Excludes virtual filesystems. | These are not real filesystems — they're kernel interfaces. Writes to `/proc/self/fd`, `/dev/null`, etc. are normal application behavior. |
| `fd.name != ""` | Excludes events with empty file descriptors. | Some syscall events may have empty `fd.name` values (e.g., anonymous pipes, sockets). Filtering these reduces false positives. |
| `not k8s.ns.name in (kube-system, kyverno)` | Excludes system namespaces. | System components may legitimately write to their container filesystems. |

---

### 🔗 Defense-in-Depth: How Kyverno and Falco Work Together

| Layer | When It Acts | What It Catches |
|---|---|---|
| **Kyverno** (Admission) | At pod creation/update | Blocks pods without `readOnlyRootFilesystem: true` — prevents writable containers from being deployed. |
| **Falco** (Runtime) | When a write syscall targets the root filesystem | Detects actual write attempts even in containers where the root FS should be read-only. |

**Key gap Falco covers:** Kyverno validates the pod spec, but cannot prevent writes to explicitly mounted volumes. Even with `readOnlyRootFilesystem: true`, writable `emptyDir` or `hostPath` mounts exist. Falco detects writes to paths *outside* expected writable directories, catching attackers who write to unexpected locations via mounted volumes.

### MITRE ATT&CK Mapping

| Tag | Technique | Description |
|---|---|---|
| `mitre_persistence` | **T1546 — Event Triggered Execution** | Attackers write malicious binaries, scripts, or configuration files to the container filesystem to establish persistence or modify application behavior. |

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

