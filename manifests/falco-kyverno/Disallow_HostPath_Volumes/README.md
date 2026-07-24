# Disallow HostPath Volumes

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Rejects any pod creation spec containing a `hostPath` volume definition. |
| **Falco Detection** | Detects reads/writes to sensitive paths on host filesystems. |

## Description
Blocks configuration of `hostPath` volumes which allow pods direct access to the node's filesystem. Monitors and alerts on access to sensitive paths (like `/etc/shadow`, `/var/run/docker.sock`) at runtime.

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
  validations:
    - message: "HostPath volumes are not allowed."
      expression: >-
        !has(object.spec.volumes) || !object.spec.volumes.exists(v, has(v.hostPath))
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
    - rule: Sensitive Host Path Accessed from Container
      desc: >

      source: syscall
        Detects a container accessing sensitive paths on the host
        filesystem via a hostPath mount.
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

## Detailed Explanation
### Kyverno Policy Manifest Explanation
The Kyverno policy protects the host directory hierarchy:
- **`validationActions`**: Set to `Deny` to block non-compliant requests at admission time.
- **`validate.pattern.spec.=(volumes)`**: Checks the volumes list.
- **`X(hostPath): "null"`**: The `X()` validation pattern represents "must not exist". If any volume specifies a `hostPath` key, the pod creation request is denied.

### Falco Rule Manifest Explanation
The companion Falco rule detects host filesystem reads/writes:
- **`evt.type in (open, openat, openat2)`**: Listens for file open syscall completions.
- **`fd.name startswith "/etc/shadow"` or `/etc/kubernetes` or `/var/run/docker.sock`**: Targets system files and sockets. If any container opens files in these paths, it generates a `CRITICAL` alert since host paths should never be exposed to runtime workloads.

## How to Test
### Kyverno (Admission Check)
Try to create a pod mounting a host path (it should be blocked immediately):
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

### Falco (Runtime Check)
Verify that any access to system critical paths like `/etc/shadow` generates a critical level alert: `Sensitive Host Path Accessed from Container`.
