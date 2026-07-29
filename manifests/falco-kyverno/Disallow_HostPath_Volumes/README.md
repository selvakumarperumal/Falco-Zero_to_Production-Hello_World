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

### Kyverno Policy Manifest Explanation
This policy prevents mounting host directory structures into containers:
- **`validationActions`**: Set to `Deny` to block non-compliant workloads at admission time.
- **CEL Expression**: `!has(object.spec.volumes) || !object.spec.volumes.exists(v, has(v.hostPath))` evaluates each volume definition in the spec. If any volume defines `hostPath`, the expression evaluates to `false` and blocks creation.
- **`autogen.podControllers`**: Automatically expands the policy to validate pod templates within `Deployments`, `DaemonSets`, `StatefulSets`, `Jobs`, and `CronJobs`.
- **`validatingAdmissionPolicy.enabled: true`**: Compiles the Kyverno policy into a native Kubernetes `ValidatingAdmissionPolicy` for high-performance in-tree admission checks.

### Falco Rule Manifest Explanation
The companion Falco rule detects unauthorized host path access at runtime:
- **`evt.type in (open, openat, openat2)`**: Intercepts file open syscalls across all Linux file opening mechanisms.
- **`container and fd.name startswith ...`**: Filters for file descriptors opened inside container environments that point to sensitive host directories.
- **Priority**: `CRITICAL` — triggers an immediate alert when a container accesses protected host files or sockets.

---

## How to Test

### Kyverno (Admission Check)
Try to deploy a pod or deployment mounting a `hostPath` volume (it should be rejected immediately by admission control):

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-hostpath
spec:
  containers:
  - name: nginx
    image: nginx
    volumeMounts:
    - mountPath: /host
      name: host-vol
  volumes:
  - name: host-vol
    hostPath:
      path: /
EOF
```

*Expected Result:*
```text
Error from server (Forbidden): admission webhook "vpol.validate.kyverno.svc-fail" denied the request:
Policy disallow-hostpath-volumes failed: HostPath volumes are not allowed.
```

### Falco (Runtime Check)
If admission control is set to `Audit` mode or bypassed, accessing system critical paths like `/etc/shadow` from a container will generate a `CRITICAL` alert in Falco: `Sensitive Host Path Accessed from Container`.
