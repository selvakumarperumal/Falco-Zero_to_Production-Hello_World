# Require Run As Non Root

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Enforces `runAsNonRoot: true` in the container securityContext. |
| **Falco Detection** | Alerts when a spawned process is executed with UID 0 (root) inside namespaces. |

## Description
Ensures containers run as non-root users (UID != 0). Monitors and alerts on root UID execution at runtime.

### 🛡️ Problem Statement — What Are We Preventing?

Running containers as root (UID 0) is one of the most common and dangerous misconfigurations in Kubernetes. Even though containers provide namespace isolation, running as root inside a container significantly increases the impact of any vulnerability:

* **Kernel Exploit Prerequisites**: The most impactful container escape vulnerabilities (CVE-2022-0185, CVE-2022-0847 "Dirty Pipe", CVE-2024-21626 "Leaky Vessels") require root privileges inside the container to exploit. Running as non-root eliminates an entire class of container escape attacks by denying the initial privilege requirement.
* **Full Filesystem Access**: A process running as UID 0 can read and write any file inside the container, including mounted secrets (`/var/run/secrets`), configuration files, and application data. A non-root process is restricted by Linux file permissions, limiting the blast radius of a compromise.
* **Process Manipulation**: Root inside a container can use `ptrace` to attach to other processes, send signals to any process, and modify the process environment — enabling injection attacks, credential harvesting, and process hijacking.
* **Device and Socket Access**: Root can access device files in `/dev`, Unix sockets, and network interfaces that would be restricted for non-root users. This enables attacks like container runtime socket abuse, raw network packet crafting, and storage device manipulation.
* **Compliance Requirement**: The Kubernetes Pod Security Standards (Restricted profile) mandates `runAsNonRoot: true`. CIS Kubernetes Benchmark control 5.2.6 requires running containers as non-root users. NIST SP 800-190 recommends running containers with the least privilege necessary.

**Kyverno prevents this** by validating that pods either set `runAsNonRoot: true` at the pod-level `securityContext` or at the individual container-level `securityContext`, blocking any pod that would run as root. **Falco detects** processes executing with UID 0 inside application containers at runtime, alerting on root execution that bypasses admission controls.


## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: require-run-as-non-root
  annotations:
    policies.kyverno.io/title: Require runAsNonRoot
    policies.kyverno.io/category: Pod Security Standards (Restricted)
    policies.kyverno.io/severity: medium
    policies.kyverno.io/description: >-
      Containers must set runAsNonRoot to true to prevent running as UID 0.
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
    - message: "Containers must not run as root. Set securityContext.runAsNonRoot to true."
      expression: >-
        (has(object.spec.securityContext) && has(object.spec.securityContext.runAsNonRoot) && object.spec.securityContext.runAsNonRoot == true) ||
        object.spec.containers.all(c, has(c.securityContext) && has(c.securityContext.runAsNonRoot) && c.securityContext.runAsNonRoot == true)
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
    - rule: Container Running as Root User
      desc: Detects a process spawned with UID 0 (root) inside an application container.
      source: syscall
      condition: >
        evt.type = execve and
        container and user.uid = 0 and
        not k8s.ns.name in (kube-system, kyverno, falco)
      output: >
        Process running as root in container (user=%user.name uid=%user.uid
        command=%proc.cmdline pod=%k8s.pod.name ns=%k8s.ns.name)
      priority: WARNING
      tags: [kyverno_companion, root_user, mitre_privilege_escalation]
```

## Detailed Explanation
### Kyverno Policy Manifest Explanation
The policy validates the execution context user:
- **`runAsNonRoot: true`**: Enforces that Kubernetes must check the image configuration (or securityContext) to verify it does not run as user UID 0.

### Falco Rule Manifest Explanation
The companion Falco rule monitors the active process UID at runtime:
- **`user.uid = 0`**: Triggers if any process spawns with UID 0 (root).
- **`not k8s.ns.name in (kube-system, kyverno)`**: Ignores cluster system processes which often require root privileges.

## How to Test
### Kyverno (Admission Check)
Attempt to deploy a standard root-default container (should be blocked):
```bash
kubectl run test-root-deploy --image=nginx --restart=Never
```

### Falco (Runtime Check)
1. Spawn a shell running as root:
```bash
kubectl run test-root-check --image=alpine --restart=Never -it -- id
```
2. Verify Falco fires: `Container Running as Root User`.
3. Clean up:
```bash
kubectl delete pod test-root-check
```
