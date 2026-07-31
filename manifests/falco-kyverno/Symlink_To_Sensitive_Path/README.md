# Symlink Created to Sensitive Path

| Property | Value |
|---|---|
| **Type** | Falco (Detection Only) |
| **Kyverno Prevention** | N/A (Runtime action). |
| **Falco Detection** | Monitors symlink syscalls aiming at system path patterns. |

## Description
Detects creation of symlinks pointing to host or container-sensitive paths (`/etc/`, `/proc/`, `/sys/`, `/var/run/`). Useful for capturing symlink-based path traversal exploits (e.g. CVE-2021-25741).

### 🛡️ Problem Statement — What Are We Preventing?

Symbolic links (symlinks) are a powerful attack primitive that allows attackers to bypass directory restrictions and access files outside their intended scope. In containerized environments, symlink attacks are a proven container escape technique:

* **Container Escape via Symlink Race (CVE-2021-25741)**: This critical Kubernetes vulnerability allowed an attacker to create a symlink inside a container that pointed to the host filesystem. By exploiting a race condition in the kubelet's volume mounting logic, the attacker could trick Kubernetes into mounting arbitrary host paths into the container — achieving full host filesystem access and container escape.
* **Path Traversal Attacks (MITRE ATT&CK: T1083)**: An attacker can create a symlink inside a container (e.g., `ln -s /etc/shadow /tmp/data`) to bypass file access controls. If any process follows the symlink (application code, logging agents, backup tools), it inadvertently reads or writes to the sensitive target file.
* **Bypassing Read-Only Root Filesystem**: Even with `readOnlyRootFilesystem: true`, writable volume mounts (e.g., `/tmp`) allow symlink creation. An attacker can create symlinks in writable directories that point to protected paths (`/proc/`, `/sys/`, `/var/run/`), bypassing the read-only protection for any process that follows symlinks.
* **Container Runtime Exploitation**: Symlinks pointing to `/proc/` or `/sys/` can be used to manipulate kernel parameters, access process memory, or interact with device files — escalating from application-level access to kernel-level control.
* **Persistent Access via /var/run/**: Symlinks to `/var/run/` can target container runtime sockets (e.g., `docker.sock`, `containerd.sock`), enabling an attacker to control the container runtime and spawn new privileged containers on the host.

**Falco detects this** by monitoring `symlink` and `symlinkat` syscalls inside containers, firing a `CRITICAL` alert when any process creates a symbolic link targeting sensitive system directories (`/etc/`, `/proc/`, `/sys/`, `/var/run/`).


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
    - rule: Symlink Created to Sensitive Path
      desc: >
        Detects creation of symbolic links pointing to sensitive paths,
        which is a common container escape technique (CVE-2021-25741).
      source: syscall
      condition: >
        evt.type in (symlink, symlinkat)
        and container
        and (evt.arg.target startswith "/etc/"
          or evt.arg.target startswith "/proc/"
          or evt.arg.target startswith "/sys/"
          or evt.arg.target startswith "/var/run/")
      output: >
        Symlink to sensitive path created (target=%evt.arg.target
        link=%fd.name command=%proc.cmdline pod=%k8s.pod.name
        ns=%k8s.ns.name)
      priority: CRITICAL
      tags: [runtime_only, symlink_attack, mitre_privilege_escalation]
```

## Detailed Explanation

### Falco Condition Breakdown

```yaml
condition: >
  evt.type in (symlink, symlinkat)
  and container
  and (evt.arg.target startswith "/etc/"
    or evt.arg.target startswith "/proc/"
    or evt.arg.target startswith "/sys/"
    or evt.arg.target startswith "/var/run/")
```

| Falco Field | What It Does | Why It's Included |
|---|---|---|
| `evt.type in (symlink, symlinkat)` | Intercepts symbolic link creation syscalls (`symlink`/`symlinkat`). | Detects creation of symlinks inside containers. |
| `container` | Scopes detection to container environments. | Ignores symlink operations on host node. |
| `evt.arg.target startswith "/etc/"` | Inspects symlink target argument to see if it points into `/etc/`. | Detects symlinks targeting system configuration and credentials. |
| `evt.arg.target startswith "/proc/"` / `"/sys/"` | Inspects if target points into virtual kernel filesystems. | Detects symlink attacks targeting kernel parameters and process data. |
| `evt.arg.target startswith "/var/run/"` | Inspects if target points to `/var/run/` (e.g. `docker.sock`). | Detects symlink attacks targeting container runtime sockets. |

---

### MITRE ATT&CK Mapping

| Tag | Technique | Description |
|---|---|---|
| `mitre_privilege_escalation` | **T1083 — File and Directory Discovery** / **CVE-2021-25741** | Symlink creation targeting sensitive system directories enables container escapes and path traversal attacks. |

## Test Scenarios & Manifest Examples

### 1. 🚨 RUNTIME ALERT CASE — Symlink Pointing to `/etc/`
```bash
# Creating a symlink inside container targeting /etc/
kubectl run test-symlink-etc --image=alpine --restart=Never -- ln -s /etc/ /tmp/test-etc
```
* **Result**: **ALERT (CRITICAL)** — `evt.type = symlink` and `evt.arg.target startswith "/etc/"`. Falco triggers `Symlink Created to Sensitive Path`.

---

### 2. 🛡️ NORMAL OPERATION — Symlink Pointing to Non-Sensitive User Path
```bash
# Creating a benign symlink between non-system paths
kubectl run test-symlink-safe --image=alpine --restart=Never -- ln -s /tmp/foo /tmp/bar
```
* **Result**: **NO ALERT** — Target path `/tmp/foo` does not start with `/etc/`, `/proc/`, `/sys/`, or `/var/run/`.

---

## How to Test

### Falco (Runtime Symlink Attack Check)
1. Run temporary pod creating a symlink to `/etc/`:
```bash
kubectl run test-symlink-creation --image=alpine --restart=Never -it -- ln -s /etc/ /tmp/test-etc
```

2. Verify Falco logs critical alert: `Symlink Created to Sensitive Path`:
```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco | grep "Symlink to sensitive path created"
```

3. Clean up:
```bash
kubectl delete pod test-symlink-creation test-symlink-etc test-symlink-safe --ignore-not-found
```

