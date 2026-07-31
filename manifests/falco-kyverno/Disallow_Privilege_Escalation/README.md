# Disallow Privilege Escalation

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Enforces `allowPrivilegeEscalation: false` on all containers. |
| **Falco Detection** | Detects spawned processes of setuid/setgid binaries like `sudo`, `su`, `passwd` at runtime. |

## Description
Ensures that `allowPrivilegeEscalation` is configured as false (preventing sub-processes from gaining more privileges than their parent). Detects execution of setuid/setgid binaries inside containers.

### 🛡️ Problem Statement — What Are We Preventing?

The Linux kernel's `no_new_privs` flag controls whether child processes can gain more privileges than their parent. When `allowPrivilegeEscalation` is not explicitly set to `false`, Kubernetes allows containers to execute setuid/setgid binaries — programs that run with the permissions of their file owner (typically root) regardless of who invokes them. This is a critical privilege escalation vector:

* **Setuid Binary Abuse (MITRE ATT&CK: T1548.001)**: Binaries like `sudo`, `su`, `passwd`, `newgrp`, `chfn`, and `pkexec` have the setuid bit set, meaning they execute with root (UID 0) privileges. An attacker who gains code execution inside a container running as a non-root user can invoke these binaries to escalate to root within the container.
* **Container Breakout Amplification**: Privilege escalation inside a container is often a prerequisite for container escape. Once running as root within the container, an attacker can exploit kernel vulnerabilities (e.g., CVE-2022-0185, CVE-2022-0847 "Dirty Pipe") that require root privileges to achieve host-level access.
* **Capability Elevation**: Even without full root access, setuid binaries can grant additional Linux capabilities. For example, `ping` uses `CAP_NET_RAW`, and a crafted setuid binary could manipulate capability sets to gain `CAP_SYS_ADMIN` or `CAP_DAC_OVERRIDE`.
* **Bypassing Non-Root Enforcement**: Organizations that enforce `runAsNonRoot: true` may believe their containers are safe from root-level attacks. However, without `allowPrivilegeEscalation: false`, a non-root container can still escalate to root via setuid binaries, undermining the non-root policy entirely.
* **Compliance Requirement**: The Kubernetes Pod Security Standards (Restricted profile) mandates `allowPrivilegeEscalation: false` as a required field. CIS Kubernetes Benchmark control 5.2.5 explicitly requires this setting.

**Kyverno prevents this** by validating that every container (including init containers) explicitly sets `allowPrivilegeEscalation: false` in its `securityContext`. **Falco detects** the runtime execution of known setuid/setgid binaries (`sudo`, `su`, `passwd`, `pkexec`, etc.) inside containers, alerting on privilege escalation attempts that bypass admission controls.


## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: disallow-privilege-escalation
  annotations:
    policies.kyverno.io/title: Disallow Privilege Escalation
    policies.kyverno.io/category: Pod Security Standards (Restricted)
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      Containers must not allow privilege escalation via setuid/setgid binaries.
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
    - message: "Privilege escalation is not allowed. Set allowPrivilegeEscalation to false."
      expression: >-
        object.spec.containers.all(c,
          has(c.securityContext) &&
          has(c.securityContext.allowPrivilegeEscalation) &&
          c.securityContext.allowPrivilegeEscalation == false
        ) &&
        object.spec.?initContainers.orValue([]).all(c,
          has(c.securityContext) &&
          has(c.securityContext.allowPrivilegeEscalation) &&
          c.securityContext.allowPrivilegeEscalation == false
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
    - rule: Setuid or Setgid Binary Executed in Container
      desc: >
        Detects execution of setuid/setgid binaries inside a container,
        which can be used for privilege escalation.
      source: syscall
      condition: >
        evt.type in (execve, execveat) and evt.failed = false and container
        and (proc.name in (sudo, su, newgrp, chsh, chfn, passwd)
          or proc.name = "pkexec")
        and not k8s.ns.name in (kube-system)
      output: >
        Setuid/setgid binary executed (command=%proc.cmdline user=%user.name
        pod=%k8s.pod.name ns=%k8s.ns.name image=%container.image.repository)
      priority: ERROR
      tags: [kyverno_companion, privilege_escalation, mitre_privilege_escalation]
```

## Detailed Explanation

### Kyverno CEL Expression Breakdown

```
object.spec.containers.all(c,
  has(c.securityContext) &&
  has(c.securityContext.allowPrivilegeEscalation) &&
  c.securityContext.allowPrivilegeEscalation == false
) &&
object.spec.?initContainers.orValue([]).all(c,
  has(c.securityContext) &&
  has(c.securityContext.allowPrivilegeEscalation) &&
  c.securityContext.allowPrivilegeEscalation == false
)
```

| CEL Fragment | What It Does | Why It's Needed |
|---|---|---|
| `object.spec.containers.all(c, ...)` | CEL list macro: every main container must pass. | All containers must explicitly disable privilege escalation. |
| `has(c.securityContext)` | Checks if `securityContext` exists. | Null-safety guard — prevents evaluation errors if securityContext is omitted. |
| `has(c.securityContext.allowPrivilegeEscalation)` | Checks if the `allowPrivilegeEscalation` field is explicitly set. | This field defaults to `true` when omitted — meaning **absence enables escalation**. The policy requires explicit `false`. |
| `c.securityContext.allowPrivilegeEscalation == false` | Validates the value is `false`. | When `false`, the Linux kernel's `no_new_privs` flag is set on the process, preventing `setuid` binaries from elevating privileges. |
| `object.spec.?initContainers.orValue([])` | Safe optional field access for init containers. | Init containers are optional. `.orValue([])` returns an empty list if absent, so `.all()` returns `true` (vacuously true). |
| `.all(c, ...)` on initContainers | Same check applied to init containers. | Init containers with `allowPrivilegeEscalation: true` could run `setuid` binaries during initialization. |

> **How `no_new_privs` works:** When `allowPrivilegeEscalation: false` is set, Kubernetes instructs the container runtime to set the Linux `no_new_privs` flag. This kernel-level flag prevents the process and all its children from gaining privileges through `execve` (which is how `setuid` binaries like `sudo` work). It's an irreversible flag — once set, it cannot be unset.

#### CEL Evaluation Trace — All Containers with `allowPrivilegeEscalation: false`

```
Step 1: Main containers: all have allowPrivilegeEscalation == false → true
Step 2: Init containers: orValue([]) → empty list → .all() returns true (vacuous)
Step 3: true && true = true → ADMITTED
```

---

### Falco Condition Breakdown

```
evt.type in (execve, execveat) and evt.failed = false and container
and (proc.name in (sudo, su, newgrp, chsh, chfn, passwd)
  or proc.name = "pkexec")
and not k8s.ns.name in (kube-system)
```

| Falco Field | What It Does | Why It's Included |
|---|---|---|
| `evt.type in (execve, execveat)` | Matches process execution syscalls. | Standard process start detection. |
| `evt.failed = false` | Only successful executions. | Failed setuid attempts (e.g., `no_new_privs` blocked it) are filtered out. |
| `container` | Event must originate inside a container. | Scopes to container workloads. |
| `proc.name in (sudo, su, newgrp, chsh, chfn, passwd)` | Matches common setuid/setgid binaries. `sudo` and `su` switch users. `newgrp` changes group. `chsh`/`chfn` modify user attributes. `passwd` changes passwords. | These binaries use the setuid bit to escalate privileges. Their execution inside a container indicates either a misconfiguration or an attacker attempting escalation. |
| `proc.name = "pkexec"` | Matches the PolicyKit execution agent. | `pkexec` (CVE-2021-4034 "PwnKit") was a major privilege escalation vulnerability in Linux. Its presence in a container is highly suspicious. |
| `not k8s.ns.name in (kube-system)` | Excludes system namespaces. | System pods may legitimately use `su` or similar tools. |

---

### 🔗 Defense-in-Depth: How Kyverno and Falco Work Together

| Layer | When It Acts | What It Catches |
|---|---|---|
| **Kyverno** (Admission) | At pod creation/update | Blocks pods without `allowPrivilegeEscalation: false`, preventing setuid binaries from gaining privileges. |
| **Falco** (Runtime) | When setuid binaries execute | Detects actual execution of privilege escalation tools, even if `no_new_privs` prevents them from succeeding. |

**Key gap Falco covers:** Even with `allowPrivilegeEscalation: false`, the setuid binaries may still be present in the container image and their *execution* (even if unsuccessful) indicates an attacker is probing the container. Falco catches the attempt before the attacker finds a kernel-level bypass.

### MITRE ATT&CK Mapping

| Tag | Technique | Description |
|---|---|---|
| `mitre_privilege_escalation` | **T1548.001 — Abuse Elevation Control: Setuid and Setgid** | Setuid binaries allow unprivileged users to execute commands as root. `allowPrivilegeEscalation: false` blocks this kernel mechanism. |

## Test Scenarios & Manifest Examples

### 1. ✅ PASS Case — Explicitly Disallows Privilege Escalation (`allowPrivilegeEscalation: false`)
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-no-priv-esc
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        allowPrivilegeEscalation: false
```
* **Result**: **PASS** — `c.securityContext.allowPrivilegeEscalation == false` evaluates to `true`.

---

### 2. ❌ FAIL Case 1 — `allowPrivilegeEscalation: true`
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-priv-esc-true
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        allowPrivilegeEscalation: true
```
* **Result**: **FAIL** — `c.securityContext.allowPrivilegeEscalation == false` evaluates to `false`.

---

### 3. ❌ FAIL Case 2 — `allowPrivilegeEscalation` Field Omitted
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-omitted-priv-esc
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
```
* **Result**: **FAIL** — `has(c.securityContext.allowPrivilegeEscalation)` evaluates to `false`. The policy requires explicit setting to `false`.

---

## How to Test

### Kyverno (Admission Control Dry-Run Check)
```bash
# 1. Test PASS case (explicitly false)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-no-priv-esc
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        allowPrivilegeEscalation: false
EOF

# 2. Test FAIL case (omitted field)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-omitted
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
EOF
```

### Falco (Runtime Execution Check)
1. Run a container and execute a setuid binary (`su`):
```bash
kubectl run test-su --image=alpine --restart=Never -it -- su
```
2. Verify Falco triggers alert: `Setuid or Setgid Binary Executed in Container`.
3. Clean up:
```bash
kubectl delete pod test-su --ignore-not-found
```

