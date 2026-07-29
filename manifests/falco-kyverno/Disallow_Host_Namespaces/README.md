# Disallow Host Namespaces

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Enforces `hostPID: false`, `hostIPC: false`, and `hostNetwork: false` on pod specifications. |
| **Falco Detection** | Detects process spawns inside containers whose pod has `k8s.pod.host_pid=true` or `k8s.pod.host_network=true`. |

## Description
Blocks pods sharing host PID, IPC, or Network namespaces (which breaks container node isolation). Detects namespace clone flags at runtime.

### 🛡️ Problem Statement — What Are We Preventing?

Host namespace sharing (`hostPID`, `hostIPC`, `hostNetwork`) is one of the most dangerous Kubernetes misconfigurations. It completely breaks the Linux namespace isolation that makes containers secure. See the detailed explanation in [Why Sharing Host Namespaces is Dangerous](#why-sharing-host-namespaces-is-dangerous) below.


---

## What is a "Host Namespace"?

Linux namespaces are the core kernel feature that makes container isolation possible. When Docker or containerd starts a container, the Linux kernel assigns it private views of system resources so the container operates as if it is the only instance on the host machine.

### Key Linux Namespace Types

| Namespace | What it Isolates |
|---|---|
| **PID** | Process IDs — container sees only its own processes (where PID 1 is its own init process). |
| **Network** | Network interfaces, IP addresses, routing tables, and port bindings. |
| **IPC** | Inter-process communication — shared memory segments, semaphores, and message queues. |
| **Mount** | Filesystem mount points. |
| **UTS** | Hostname and NIS domain name. |

Under standard container runtime settings, a container receives an isolated copy of each namespace.

---

## Why Sharing Host Namespaces is Dangerous

Setting `hostPID: true`, `hostIPC: true`, or `hostNetwork: true` in a Kubernetes Pod spec instructs the runtime **not** to isolate the container for that subsystem, sharing the host node's own namespace directly instead.

* **`hostPID: true`**:
  - The container can see every process running on the host node (including `kubelet`, `containerd`, system daemons, and processes of all other pods).
  - Combined with elevated privileges, an attacker can attach to (`ptrace`) or kill processes running on the host node.
* **`hostNetwork: true`**:
  - The pod bypasses virtual network interfaces and uses the host node's network stack directly.
  - It can bind to host ports, sniff network traffic, and bypass network policies.
* **`hostIPC: true`**:
  - The container can read/write shared memory segments used by host processes and other pods sharing host IPC.

> [!WARNING]
> These flags act as opt-out switches for container isolation. A pod running with all three flags disabled for isolation is effectively running directly on the host node, making it a critical container breakout and privilege escalation vector (**MITRE ATT&CK: Privilege Escalation**). This is why restricting host namespaces is a fundamental requirement of the Kubernetes Pod Security Standards (Baseline & Restricted profiles).

---

## Two-Layer Defense-in-Depth (Kyverno + Falco)

### 1. Kyverno (Admission Time Prevention)
Kyverno intercepts `Pod` `CREATE` and `UPDATE` API requests using a CEL validation rule:

```cel
!(has(object.spec.hostPID) && object.spec.hostPID == true) &&
!(has(object.spec.hostIPC) && object.spec.hostIPC == true) &&
!(has(object.spec.hostNetwork) && object.spec.hostNetwork == true)
```

If any of these fields are set to `true`, Kyverno blocks pod creation at admission before the pod is ever scheduled onto a node.

### 2. Falco (Runtime Detection)
If admission controls are bypassed (e.g. audit mode, emergency override, or direct node access), Falco acts as the safety net by inspecting spawned processes inside containers and checking Kubernetes pod metadata for host namespace configurations (`k8s.pod.host_pid=true` or `k8s.pod.host_network=true`).

---

## Kyverno Policy Manifest

```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: disallow-host-namespaces
  annotations:
    policies.kyverno.io/title: Disallow Host Namespaces
    policies.kyverno.io/category: Pod Security Standards (Baseline)
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      Containers must not share the host PID, IPC, or network namespaces.
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
    - message: "Host PID, IPC, and network namespaces are not allowed."
      expression: >-
        !(has(object.spec.hostPID) && object.spec.hostPID == true) &&
        !(has(object.spec.hostIPC) && object.spec.hostIPC == true) &&
        !(has(object.spec.hostNetwork) && object.spec.hostNetwork == true)
```

---

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
    - rule: Container Running with Host PID or Network
      desc: Detects a running container whose pod uses host PID or network namespace.
      condition: >
        spawned_process and container and
        (k8s.pod.host_pid=true or k8s.pod.host_network=true)
      output: >
        Container running with host namespace (user=%user.name pod=%k8s.pod.name
        ns=%k8s.ns.name image=%container.image.repository
        hostpid=%k8s.pod.host_pid hostnetwork=%k8s.pod.host_network)
      priority: CRITICAL
      tags: [kyverno_companion, host_namespace, mitre_privilege_escalation]
```

---

## Detailed Explanation

### Kyverno Policy Manifest Explanation
This policy prevents container breakout to host namespaces:
- **`validationActions`**: Set to `Deny` to block non-compliant requests at admission time.
- **CEL Expression**: Checks `hostPID`, `hostIPC`, and `hostNetwork` fields on `object.spec`. If any are `true`, validation returns `false` and blocks creation.

### Falco Rule Manifest Explanation
The Falco check catches namespace sharing at runtime:
- **`spawned_process and container`**: Triggers whenever a new process is spawned within a container context.
- **`k8s.pod.host_pid=true or k8s.pod.host_network=true`**: Uses Kubernetes metadata enrichment to check if the pod shares host PID or Network namespaces, firing a `CRITICAL` alert containing `hostpid` and `hostnetwork` metadata values.

---

## Test Scenarios & Manifest Examples

### 1. ✅ PASS Case — Standard Isolated Pod (No Host Namespaces)
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-isolated-ns
  namespace: default
spec:
  hostPID: false
  hostIPC: false
  hostNetwork: false
  containers:
    - name: app
      image: nginx:1.25
```
* **Result**: **PASS** — All host namespace flags evaluate to `false` or are omitted (defaulting to isolated).

---

### 2. ❌ FAIL Case 1 — Pod Sharing Host PID Namespace (`hostPID: true`)
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-host-pid
  namespace: default
spec:
  hostPID: true
  containers:
    - name: app
      image: nginx:1.25
```
* **Result**: **FAIL** — `object.spec.hostPID == true` violates rule `!(has(hostPID) && hostPID == true)`.

---

### 3. ❌ FAIL Case 2 — Pod Sharing Host Network Namespace (`hostNetwork: true`)
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-host-network
  namespace: default
spec:
  hostNetwork: true
  containers:
    - name: app
      image: nginx:1.25
```
* **Result**: **FAIL** — `object.spec.hostNetwork == true` violates policy validations.

---

### 4. ❌ FAIL Case 3 — Pod Sharing Host IPC Namespace (`hostIPC: true`)
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-host-ipc
  namespace: default
spec:
  hostIPC: true
  containers:
    - name: app
      image: nginx:1.25
```
* **Result**: **FAIL** — `object.spec.hostIPC == true` is denied.

---

## How to Test

### Kyverno (Admission Control Dry-Run Check)
```bash
# 1. Test PASS case (isolated pod should succeed)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-isolated
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
EOF

# 2. Test FAIL case (hostPID pod should be blocked)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-host-pid
  namespace: default
spec:
  hostPID: true
  containers:
    - name: app
      image: nginx:1.25
EOF
```

### Falco (Runtime Check)
If admission control is bypassed or in audit-only mode, starting a container with host namespaces will fire the alert: `Container Running with Host PID or Network`.

