# Drop All Capabilities

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Ensures `ALL` is listed in the dropped capabilities array of container definitions. |
| **Falco Detection** | Monitors syscalls indicating dangerous capability manipulation. |

## Description
Enforces the best practice of dropping all default Linux capabilities on containers. Detects usage of tools interacting with namespaces/capabilities (e.g. `unshare`, `nsenter`, `capsh`) at runtime.

### 🛡️ Problem Statement — What Are We Preventing?

Linux capabilities split the monolithic root privilege into ~40 discrete permissions (e.g., `CAP_NET_RAW`, `CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`). By default, Docker and containerd grant containers a set of ~14 capabilities, many of which are unnecessary and dangerous for typical application workloads:

* **Default Capabilities Enable Attacks**: The default capability set includes `CAP_NET_RAW` (raw socket creation for network sniffing/ARP spoofing), `CAP_SETUID`/`CAP_SETGID` (changing process user/group IDs), `CAP_FOWNER` (bypassing file ownership checks), and others that provide attack primitives for privilege escalation and lateral movement.
* **Container Escape via CAP_SYS_ADMIN**: `CAP_SYS_ADMIN` is the most dangerous capability — it enables mounting filesystems, modifying kernel parameters, using `ptrace`, creating namespaces, and loading eBPF programs. A container with `CAP_SYS_ADMIN` can trivially escape to the host. While not granted by default, failing to drop ALL capabilities and then selectively adding only needed ones leaves room for misconfigurations where `CAP_SYS_ADMIN` is accidentally granted.
* **Network-Level Attacks**: `CAP_NET_RAW` allows containers to craft arbitrary network packets, enabling ARP spoofing, DNS poisoning, and man-in-the-middle attacks against other pods on the same node — even without privileged mode.
* **File System Bypass**: Capabilities like `CAP_DAC_OVERRIDE` and `CAP_DAC_READ_SEARCH` allow processes to bypass file permission checks entirely, reading any file on the filesystem regardless of ownership — including mounted secrets and configuration files.
* **Compliance and PSS Requirement**: The Kubernetes Pod Security Standards (Restricted profile) requires containers to drop ALL capabilities and only add back specific ones explicitly needed. CIS Kubernetes Benchmark control 5.2.7 mandates this practice.

**Kyverno prevents this** by validating that every container's `securityContext.capabilities.drop` list includes `ALL`, ensuring all capabilities are dropped at the kernel level before the container starts. **Falco detects** runtime usage of capability and namespace manipulation tools (`nsenter`, `unshare`, `capsh`) that indicate an attacker is attempting to elevate privileges or escape the container sandbox.


## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: drop-all-capabilities
  annotations:
    policies.kyverno.io/title: Drop All Capabilities
    policies.kyverno.io/category: Pod Security Standards (Restricted)
    policies.kyverno.io/severity: medium
    policies.kyverno.io/description: >-
      Containers must drop ALL Linux capabilities. Only explicitly needed
      capabilities should be added back.
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
    - message: "Containers must drop ALL capabilities."
      expression: >-
        object.spec.containers.all(c,
          has(c.securityContext) &&
          has(c.securityContext.capabilities) &&
          has(c.securityContext.capabilities.drop) &&
          c.securityContext.capabilities.drop.exists(x, x == 'ALL')
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
    - rule: Dangerous Capability Used at Runtime
      desc: >
        Detects a process attempting to use dangerous Linux capabilities
        such as SYS_ADMIN, SYS_PTRACE, or NET_RAW.
      source: syscall
      condition: >
        evt.type in (execve, execveat) and evt.failed = false and container
        and (proc.name = "nsenter" or proc.name = "unshare"
          or proc.cmdline contains "capsh"
          or proc.cmdline contains "--cap-add")
      output: >
        Dangerous capability usage detected (command=%proc.cmdline
        user=%user.name pod=%k8s.pod.name ns=%k8s.ns.name)
      priority: WARNING
      tags: [kyverno_companion, capabilities, mitre_privilege_escalation]
```

## Detailed Explanation
#### Truth Table — Kyverno CEL Evaluation

| `has(securityContext)` | `has(capabilities.drop)` | Includes `'ALL'` | Expression Result | Policy Decision |
|---|---|---|---|---|
| `false` | — | — | `false` | **FAIL** |
| `true` | `true` | `['NET_ADMIN']` (missing `'ALL'`) | `false` | **FAIL** |
| `true` | `true` | `['ALL']` | `true` | **PASS** |

#### Truth Table — Falco Runtime Detections

| `container` | Process / Command Pattern | Falco Alert Result |
|---|---|---|
| `true` | `nginx` | No Alert |
| `true` | `nsenter` / `unshare` / `capsh` / `--cap-add` | **ALERT FIRED (CRITICAL)** |



### Kyverno CEL Expression Breakdown

```
object.spec.containers.all(c,
  has(c.securityContext) &&
  has(c.securityContext.capabilities) &&
  has(c.securityContext.capabilities.drop) &&
  c.securityContext.capabilities.drop.exists(x, x == 'ALL')
)
```

| CEL Fragment | What It Does | Why It's Needed |
|---|---|---|
| `object.spec.containers.all(c, ...)` | CEL list macro: every container must satisfy the predicate. | All containers must drop all capabilities — one container retaining capabilities creates a privilege escalation path. |
| `has(c.securityContext)` | Checks if `securityContext` exists on the container. | Guards against null reference. |
| `has(c.securityContext.capabilities)` | Checks if the `capabilities` block exists. | The `capabilities` field is optional — if absent, the container gets the default set (which includes dangerous capabilities like `NET_RAW`, `CHOWN`, `SETUID`). |
| `has(c.securityContext.capabilities.drop)` | Checks if the `drop` list exists within capabilities. | A container can have `capabilities.add` without `capabilities.drop` — we must explicitly verify that capabilities are being dropped. |
| `c.securityContext.capabilities.drop.exists(x, x == 'ALL')` | CEL list macro: returns `true` if at least one element in the `drop` list equals the string `'ALL'`. | `DROP ALL` is a Linux kernel convention meaning "remove every capability." The `.exists()` macro checks that the `ALL` token is present in the drop list — it may appear alongside specific adds like `NET_BIND_SERVICE`. |

#### Linux Capabilities — What Gets Dropped

When `drop: ["ALL"]` is set, the container loses these capabilities (among others):

| Capability | What It Allows | Risk If Not Dropped |
|---|---|---|
| `NET_RAW` | Create raw sockets, send arbitrary packets | ARP spoofing, DNS poisoning, network sniffing |
| `SYS_ADMIN` | Broad system administration (mount, namespace manipulation) | Container escape via namespace manipulation |
| `SYS_PTRACE` | Trace and debug other processes | Read memory of other containers on the same node |
| `CHOWN` | Change file ownership | Modify ownership of sensitive files |
| `SETUID` / `SETGID` | Change process UID/GID | Escalate from non-root to root |
| `DAC_OVERRIDE` | Bypass file permission checks | Read/write any file regardless of permissions |

#### CEL Evaluation Trace — Container with `drop: ["ALL"]`

```
Step 1: has(c.securityContext) → true
Step 2: has(c.securityContext.capabilities) → true
Step 3: has(c.securityContext.capabilities.drop) → true
Step 4: c.securityContext.capabilities.drop = ["ALL"]
        → .exists(x, x == 'ALL') → x = "ALL", "ALL" == "ALL" → true
Step 5: .all() returns true → ADMITTED
```

#### CEL Evaluation Trace — Container with Specific Drops (Not `ALL`)

```
Step 1-3: has() checks pass
Step 4: c.securityContext.capabilities.drop = ["NET_RAW", "SYS_ADMIN"]
        → .exists(x, x == 'ALL') → neither element equals "ALL" → false
Step 5: Predicate returns false → .all() returns false → DENIED
```

---

### Falco Condition Breakdown

```
evt.type in (execve, execveat) and evt.failed = false and container
and (proc.name = "nsenter" or proc.name = "unshare"
  or proc.cmdline contains "capsh"
  or proc.cmdline contains "--cap-add")
```

| Falco Field | What It Does | Why It's Included |
|---|---|---|
| `evt.type in (execve, execveat)` | Matches process execution syscalls. | Standard process start detection. |
| `evt.failed = false` | Only successful executions. | Failed attempts are not actionable. |
| `container` | Event must originate inside a container. | Host-level system tools like `nsenter` are used legitimately by `kubelet`. |
| `proc.name = "nsenter"` | Detects the `nsenter` binary, which enters Linux namespaces. | `nsenter` is the primary tool for container escape — `nsenter --target 1 --mount --uts --ipc --net --pid` enters the host's namespaces. |
| `proc.name = "unshare"` | Detects the `unshare` binary, which creates new namespaces. | `unshare` can be used to create a new user namespace with elevated capabilities, bypassing capability restrictions. |
| `proc.cmdline contains "capsh"` | Detects usage of the capabilities shell tool. | `capsh` is used to inspect and manipulate Linux capabilities at runtime — its presence indicates someone is probing or modifying capability sets. |
| `proc.cmdline contains "--cap-add"` | Detects Docker/containerd commands adding capabilities. | If an attacker has access to the container runtime socket, they could add capabilities to a running or new container. |

---

### 🔗 Defense-in-Depth: How Kyverno and Falco Work Together

| Layer | When It Acts | What It Catches |
|---|---|---|
| **Kyverno** (Admission) | At pod creation/update | Blocks pods that don't drop all capabilities in their security context. |
| **Falco** (Runtime) | When capability-manipulation tools execute | Detects runtime attempts to use or escalate capabilities, even if the pod spec correctly drops them. |

**Key gap Falco covers:** Kyverno ensures capabilities are dropped in the pod spec, but cannot prevent exploitation at runtime. An attacker could exploit a kernel vulnerability to gain capabilities that were dropped, or use `capsh` to inspect what capabilities are actually available. Falco detects these probing/exploitation tools at the syscall level.

### MITRE ATT&CK Mapping

| Tag | Technique | Description |
|---|---|---|
| `mitre_privilege_escalation` | **T1611 — Escape to Host** | Linux capabilities like `SYS_ADMIN` and `SYS_PTRACE` are the primary enablers for container escape. Dropping ALL eliminates these vectors. |

## Test Scenarios & Manifest Examples

### 1. ✅ PASS Case — Explicitly Drops `ALL`
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-drop-all
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        capabilities:
          drop:
            - ALL
```
* **Result**: **PASS** — The container's `securityContext.capabilities.drop` array contains `ALL`.

---

### 2. ❌ FAIL Case — No `securityContext` Block
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-no-context
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
```
* **Result**: **FAIL** — `has(c.securityContext)` evaluates to `false`.

---

### 3. ❌ FAIL Case — `securityContext` Present, Missing `capabilities`
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-no-drop
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        runAsNonRoot: true
```
* **Result**: **FAIL** — `has(c.securityContext.capabilities)` evaluates to `false`.

---

### 4. ❌ FAIL Case — Drops Partial Capabilities, But Not `ALL`
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-partial-drop
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        capabilities:
          drop:
            - NET_RAW
            - SYS_ADMIN
```
* **Result**: **FAIL** — `drop.exists(x, x == 'ALL')` evaluates to `false` because `ALL` is not explicitly listed in the `drop` array.

---

### 5. ✅ Realistic Production PASS Case — Drop `ALL`, Add Back Specific Needed Capability
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-drop-all-add-net-bind
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        capabilities:
          drop:
            - ALL
          add:
            - NET_BIND_SERVICE
```
* **Result**: **PASS** — The policy validates that `ALL` is in the `drop` array; it permits adding specific required capabilities back (e.g. `NET_BIND_SERVICE` for binding to privileged ports <1024 as non-root).

---

## How to Test

### Kyverno (Admission Control Check)
Test against the admission webhook in server dry-run mode without persisting test resources to the cluster:

```bash
# 1. Test PASS case (should be allowed)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-drop-all
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        capabilities:
          drop:
            - ALL
EOF

# 2. Test FAIL case (should be denied)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-no-context
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
EOF
```

### Falco (Runtime Check)
1. Run a shell and invoke a capability/namespace manipulation utility inside a container:
```bash
kubectl run test-cap-use --image=alpine --restart=Never -it -- unshare -h
```
2. Verify Falco triggers alert: `Dangerous Capability Used at Runtime`.
3. Clean up:
```bash
kubectl delete pod test-cap-use --ignore-not-found
```

