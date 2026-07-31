# Disallow HostPath Volumes

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Rejects pods and workload controllers (`Deployments`, `DaemonSets`, `StatefulSets`, `Jobs`, `CronJobs`) specifying `hostPath` volumes. |
| **Falco Detection** | Detects open/read access to sensitive host paths (`/etc/shadow`, `/etc/kubernetes`, `/var/run/docker.sock`, `/root/.ssh`, `/root/.kube`) from containers. |

## Description
Blocks the configuration of `hostPath` volumes in Kubernetes pods and workload controllers. HostPath volumes grant containers direct access to the underlying host node filesystem, bypassing container sandbox boundaries. Automatically generates controller rules via Kyverno `autogen` and monitors runtime access to critical host files using Falco.

### 🛡️ Problem Statement — What Are We Preventing?

HostPath volumes allow containers to directly access the host node's filesystem — bypassing all container sandbox protections. This enables container escape, credential theft, and full host compromise. See the detailed explanation in [What is a HostPath Volume & Why is it Dangerous?](#what-is-a-hostpath-volume--why-is-it-dangerous) below.


---

## What is a HostPath Volume & Why is it Dangerous?

A `hostPath` volume mounts a file or directory from the host node's filesystem directly into a container. While useful for specific node daemon utilities (e.g. log collectors or monitoring agents), allowing arbitrary pods to mount `hostPath` volumes presents severe security risks:

* **Container Escape & Host Compromise**: A container mounting `/` or sensitive host directories can edit host system files, insert SSH keys into `/root/.ssh`, or edit `/etc/shadow` to gain root access on the worker node.
* **Docker Socket Abuse**: Mounting `/var/run/docker.sock` or container runtime sockets allows a container to issue commands to the host container runtime, spinning up privileged containers or taking over the node.
* **Credential Theft**: Mounting `/etc/kubernetes` or `/root/.kube` exposes cluster admin certificates, tokens, and node configuration parameters.

> [!WARNING]
> Restricting `hostPath` volumes is a key requirement of both the **Baseline** and **Restricted** profiles of the Kubernetes Pod Security Standards (PSS) and **MITRE ATT&CK: Privilege Escalation & Credential Access**.

---

## Two-Layer Defense-in-Depth (Kyverno + Falco)

### 1. Kyverno (Admission Time Prevention)
Kyverno intercepts API requests for `Pods` as well as higher-level workload controllers using `autogen` (`Deployments`, `DaemonSets`, `StatefulSets`, `Jobs`, `CronJobs`):

```cel
!has(object.spec.volumes) || !object.spec.volumes.exists(v, has(v.hostPath))
```

* **Logic**: If the resource has no `volumes` defined, it passes. If `volumes` exists, Kyverno verifies that **no** item `v` in `object.spec.volumes` contains a `hostPath` property.
* **Autogen & VAP**: The policy uses `autogen.podControllers` to automatically generate validation rules for pod controllers and enables `validatingAdmissionPolicy` for native Kubernetes CEL admission enforcement.

### 2. Falco (Runtime Detection)
If a pod with `hostPath` volumes is deployed (or created directly by a node component), Falco acts as a secondary layer by monitoring file open syscalls (`open`, `openat`, `openat2`) targeting critical paths:

```falco
evt.type in (open, openat, openat2) and container and (
  fd.name startswith "/etc/shadow" or
  fd.name startswith "/etc/kubernetes" or
  fd.name startswith "/var/run/docker.sock" or
  fd.name startswith "/root/.ssh" or
  fd.name startswith "/root/.kube"
)
```

---

## Kyverno Policy Manifest

```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: disallow-hostpath-volumes
  annotations:
    policies.kyverno.io/title: Disallow HostPath Volumes
    policies.kyverno.io/category: Pod Security Standards (Baseline)
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      HostPath volumes give containers direct access to the node filesystem.
      This policy blocks all hostPath volume mounts.
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
  autogen:
    podControllers:
      controllers:
        - deployments
        - daemonsets
        - statefulsets
        - jobs
        - cronjobs
    validatingAdmissionPolicy:
      enabled: true
  validations:
    - message: "HostPath volumes are not allowed."
      expression: >-
        !has(object.spec.volumes) || !object.spec.volumes.exists(v, has(v.hostPath))
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
    - rule: Sensitive Host Path Accessed from Container
      desc: >
        Detects a container accessing sensitive paths on the host
        filesystem via a hostPath mount.
      source: syscall
      condition: >
        evt.type in (open, openat, openat2)
        and container
        and (fd.name startswith "/etc/shadow"
          or fd.name startswith "/etc/kubernetes"
          or fd.name startswith "/var/run/docker.sock"
          or fd.name startswith "/root/.ssh"
          or fd.name startswith "/root/.kube")
      output: >
        Sensitive host path accessed from container (file=%fd.name
        command=%proc.cmdline pod=%k8s.pod.name ns=%k8s.ns.name)
      priority: CRITICAL
      tags: [kyverno_companion, hostpath, mitre_credential_access]
```

---

## Detailed Explanation
#### Truth Table — Kyverno CEL Evaluation

| `has(spec.volumes)` | Volume Has `hostPath` | `!has(v.hostPath)` | `volumes.all(...)` | Policy Decision |
|---|---|---|---|---|
| `false` (no volumes) | — | `true` | `true` | **PASS** |
| `true` | `false` (`emptyDir`, `configMap`) | `true` | `true` | **PASS** |
| `true` | `true` (`hostPath: {path: /var/run}`) | `false` | `false` | **FAIL** |

#### Truth Table — Falco Runtime Detections

| `evt.type` | `container` | Target Mount Path (`fd.name`) | Falco Alert Result |
|---|---|---|---|
| `open` / `openat` | `true` | `/var/log/app.log` | No Alert |
| `open` / `openat` | `true` | `/var/run/docker.sock` / `/etc/kubernetes/` | **ALERT FIRED (CRITICAL)** |



### Kyverno CEL Expression Breakdown

```
!has(object.spec.volumes) || !object.spec.volumes.exists(v, has(v.hostPath))
```

| CEL Fragment | What It Does | Why It's Needed |
|---|---|---|
| `!has(object.spec.volumes)` | Checks if the pod has no `volumes` field defined. | If a pod has no volumes at all, it cannot have hostPath volumes — short-circuits to `true` (admitted). |
| `\|\|` (OR) | If volumes is missing, admit immediately; otherwise evaluate the volume list. | Prevents evaluation error when `.volumes` is null/omitted. |
| `object.spec.volumes.exists(v, ...)` | CEL list macro: returns `true` if **at least one** volume `v` contains a `hostPath` field. | Scans all volume definitions in the pod spec. |
| `has(v.hostPath)` | Checks if the `hostPath` field exists on volume `v`. | Identifies if this specific volume is mounting a directory or file from the host filesystem. |
| `!...exists(...)` | Negates the result — returns `true` only if **no** volume has a `hostPath`. | Kyverno requires `true` for admission. |

#### CEL Evaluation Trace — Pod with HostPath Volume

```
Step 1: has(object.spec.volumes) → true
Step 2: object.spec.volumes.exists(v, has(v.hostPath)) → volume "host-root" has hostPath → true
Step 3: !true → false
Step 4: false || false → false → DENIED
```

---

### Falco Condition Breakdown

```
evt.type in (open, openat, openat2) and container
and (fd.name startswith "/etc/shadow"
  or fd.name startswith "/etc/kubernetes"
  or fd.name startswith "/var/run/docker.sock"
  or fd.name startswith "/root/.ssh"
  or fd.name startswith "/root/.kube")
```

| Falco Field | What It Does | Why It's Included |
|---|---|---|
| `evt.type in (open, openat, openat2)` | Intercepts file open syscalls across all Linux file opening mechanisms. | Detects when a container process attempts to access files. |
| `container` | Ensures the event originates from inside a container. | Prevents false positives from host processes accessing system files. |
| `fd.name startswith "/etc/shadow"` | Checks if file descriptor targets `/etc/shadow` (password hashes). | Accessing host credentials from container indicates hostPath abuse. |
| `fd.name startswith "/etc/kubernetes"` | Targets Kubernetes node configuration and PKI keys. | Protects cluster control plane credentials from container exposure. |
| `fd.name startswith "/var/run/docker.sock"` | Targets container runtime socket. | Mounting the container socket allows full host takeover and container escape. |
| `fd.name startswith "/root/.ssh"` / `"/root/.kube"` | Targets root SSH keys or admin kubeconfig files. | Detects credential harvesting via hostPath mounts. |

---

### 🔗 Defense-in-Depth: How Kyverno and Falco Work Together

| Layer | When It Acts | What It Catches |
|---|---|---|
| **Kyverno** (Admission) | At pod creation/update | Blocks any pod manifest that defines a `hostPath` volume at admission time. |
| **Falco** (Runtime) | When a process opens a file | Detects file access to sensitive host paths inside containers if admission controls were bypassed or set to Audit mode. |

### MITRE ATT&CK Mapping

| Tag | Technique | Description |
|---|---|---|
| `mitre_credential_access` | **T1003 — OS Credential Dumping** / **T1611 — Escape to Host** | HostPath mounts allow containers to directly read host secrets, sockets, and credential files. |

---

## Test Scenarios & Manifest Examples

### 1. ✅ PASS Case — Standard `emptyDir` Volume
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-emptydir
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      volumeMounts:
        - mountPath: /tmp/cache
          name: cache-vol
  volumes:
    - name: cache-vol
      emptyDir: {}
```
* **Result**: **PASS** — Volume specifies `emptyDir`, so `has(v.hostPath)` evaluates to `false`.

---

### 2. ❌ FAIL Case — Direct `hostPath` Mount on Pod
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-hostpath-pod
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      volumeMounts:
        - mountPath: /host-etc
          name: host-vol
  volumes:
    - name: host-vol
      hostPath:
        path: /etc
```
* **Result**: **FAIL** — `object.spec.volumes.exists(v, has(v.hostPath))` evaluates to `true`, violating the policy rule.

---

### 3. ❌ FAIL Case — `hostPath` Mount in Deployment Template (Caught by Autogen)
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-fail-hostpath-deploy
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: bad-hostpath
  template:
    metadata:
      labels:
        app: bad-hostpath
    spec:
      containers:
        - name: app
          image: nginx:1.25
          volumeMounts:
            - mountPath: /host-root
              name: root-vol
      volumes:
        - name: root-vol
          hostPath:
            path: /
```
* **Result**: **FAIL** — The `autogen.podControllers` block generates rules covering `Deployments`, rejecting creation at admission time.

---

## How to Test

### Kyverno (Admission Control Dry-Run Check)
```bash
# 1. Test PASS case (should succeed)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-emptydir
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      volumeMounts:
        - mountPath: /tmp/cache
          name: cache-vol
  volumes:
    - name: cache-vol
      emptyDir: {}
EOF

# 2. Test FAIL case (should be blocked)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-hostpath-pod
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:1.25
      volumeMounts:
        - mountPath: /host-etc
          name: host-vol
  volumes:
    - name: host-vol
      hostPath:
        path: /etc
EOF
```

### Falco (Runtime Access Check)
If admission control is in `Audit` mode or bypassed, accessing system critical paths like `/etc/shadow` from a container will generate a `CRITICAL` alert in Falco: `Sensitive Host Path Accessed from Container`.

