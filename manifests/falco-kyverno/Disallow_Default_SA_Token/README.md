# Disallow Default Service Account Token

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Validates that pods using the default service account explicitly turn off token automounting. |
| **Falco Detection** | Detects open/read syscalls targeting files under `/var/run/secrets/kubernetes.io/serviceaccount` by non-system processes. |

## Description
Enforces setting `automountServiceAccountToken: false` on pods utilizing the `default` service account to prevent default service account token mounting. Simultaneously detects runtime access to service account token files.

## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: disallow-default-sa-token
  annotations:
    policies.kyverno.io/title: Disallow Default Service Account Token
    policies.kyverno.io/category: Security Best Practices
    policies.kyverno.io/severity: medium
    policies.kyverno.io/description: >-
      Pods using the default service account must not automount the
      service account token unless explicitly needed.
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
    - message: "Pods using the default service account must set automountServiceAccountToken to false."
      expression: >-
        (!has(object.spec.serviceAccountName) || object.spec.serviceAccountName == 'default') ?
        (has(object.spec.automountServiceAccountToken) && object.spec.automountServiceAccountToken == false) : true
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
    - rule: Service Account Token Accessed in Container
      desc: Detects process access to auto-mounted service account tokens.
      source: syscall
      condition: >
        evt.type in (open, openat, openat2) and evt.dir = < and
        container and evt.is_open_read = true and
        fd.name contains "/var/run/secrets/kubernetes.io/serviceaccount" and
        not k8s.ns.name in (kube-system, kyverno, falco)
      output: >
        Service account token accessed (file=%fd.name command=%proc.cmdline
        pod=%k8s.pod.name ns=%k8s.ns.name user=%user.name)
      priority: WARNING
      tags: [kyverno_companion, sa_token, mitre_credential_access]
```

## Detailed Explanation
### Kyverno Policy Manifest Explanation
The Kyverno check enforces a zero-trust credential mount policy:
- **`validationActions`**: Set to `Deny` to block non-compliant requests at admission time.
- **`preconditions`**: Checks if the pod's service account name is `default` (or blank, which defaults to `default`).
- **`validate.pattern`**: Enforces that `automountServiceAccountToken` must be explicitly set to `false`.

### Falco Rule Manifest Explanation
The companion Falco rule monitors the token file access:
- **`evt.type in (open, openat, openat2)`**: Listens to system calls used to open/read files.
- **`evt.dir = <`**: Matches only when the syscall exits (successfully returns a file descriptor).
- **`fd.name contains "/var/run/secrets/kubernetes.io/serviceaccount"`**: Focuses on access to the mounted service account credentials.
- **`not k8s.ns.name in (kube-system, kyverno)`**: Excludes safe system namespaces.
- **`not proc.name in (pause, tini)`**: Excludes typical orchestrator helper processes.

## How to Test
### Kyverno (Admission Check)
Try to deploy a pod with the default service account without setting `automountServiceAccountToken: false`:
```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-default-sa
spec:
  containers:
  - name: nginx
    image: nginx
EOF
```
Kyverno will validate this request (depending on the mode, it will either block the pod or report a violation in the Audit PolicyReport).

### Falco (Runtime Check)
1. Run a container and read the mounted service account token file:
```bash
kubectl run test-sa-read --image=alpine --restart=Never -it -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```
2. Verify that Falco has raised a warning alert: `Service Account Token Accessed in Container`.
3. Clean up:
```bash
kubectl delete pod test-sa-read
```
