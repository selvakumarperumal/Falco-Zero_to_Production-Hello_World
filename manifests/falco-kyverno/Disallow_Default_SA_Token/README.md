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
        evt.type in (open, openat, openat2) and
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
The Kyverno check enforces a zero-trust credential mount policy using CEL ternary logic:
```cel
(!has(object.spec.serviceAccountName) || object.spec.serviceAccountName == 'default') ?
(has(object.spec.automountServiceAccountToken) && object.spec.automountServiceAccountToken == false) : true
```

---

## Test Scenarios & CEL Logic Trace

### Scenario 1 — Default ServiceAccount (Condition = `true`, Check Evaluated)

#### ❌ FAILS — Implicit default SA without token opt-out (`test-default-sa-fail.yaml`)
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-default-sa-fail
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:latest
```
- **Trace:** `!has(serviceAccountName)` → `true` → condition evaluates to `true` → true-branch: `has(automountServiceAccountToken)` → `false` → overall result: `false` (Violation).

#### ✅ PASSES — Implicit default SA with token opt-out (`test-default-sa-pass.yaml`)
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-default-sa-pass
  namespace: default
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: nginx:latest
```
- **Trace:** Condition evaluates to `true` (implicit default) → true-branch: `has(automountServiceAccountToken)` → `true`, `automountServiceAccountToken == false` → `true` → overall result: `true` (Compliant).

---

### Scenario 2 — Custom ServiceAccount (Condition = `false`, Policy Skips Check)

#### ✅ PASSES — Custom SA (`test-custom-sa.yaml`)
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app-sa
  namespace: default
---
apiVersion: v1
kind: Pod
metadata:
  name: test-custom-sa
  namespace: default
spec:
  serviceAccountName: my-app-sa
  containers:
    - name: app
      image: nginx:latest
```
- **Trace:** `!has(serviceAccountName)` → `false`; `serviceAccountName == 'default'` → `false`. Condition `false || false` → `false` → ternary takes the `: true` fallback branch immediately → overall result: `true` (Always passes, regardless of `automountServiceAccountToken`).

---

## How to Test

### Kyverno (Admission Check)

#### 1. Testing in Audit Mode
When `validationActions: [Audit]`, all three manifests can be applied:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-default-sa-fail
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:latest
---
apiVersion: v1
kind: Pod
metadata:
  name: test-default-sa-pass
  namespace: default
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: nginx:latest
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app-sa
  namespace: default
---
apiVersion: v1
kind: Pod
metadata:
  name: test-custom-sa
  namespace: default
spec:
  serviceAccountName: my-app-sa
  containers:
    - name: app
      image: nginx:latest
EOF
```

Check the generated PolicyReport:
```bash
kubectl get policyreport -n default
kubectl describe policyreport -n default
```
*Result:* `test-default-sa-fail` is reported as `fail`, while `test-default-sa-pass` and `test-custom-sa` are reported as `pass`.

#### 2. Testing in Enforce Mode
When `validationActions: [Deny]`, applying `test-default-sa-fail` will be rejected immediately at `kubectl apply` time:
```text
Error from server (Forbidden): admission webhook "vpol.validate.kyverno.svc-fail" denied the request:
Policy disallow-default-sa-token failed: Pods using the default service account must set automountServiceAccountToken to false.
```

### Falco (Runtime Check)
1. Run a container and read the mounted service account token file:
```bash
kubectl run test-sa-read --image=alpine --restart=Never -it -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```
2. Verify that Falco has raised a warning alert: `Service Account Token Accessed in Container`.
3. Clean up:
```bash
kubectl delete pod test-sa-read test-default-sa-fail test-default-sa-pass test-custom-sa --ignore-not-found
kubectl delete sa my-app-sa -n default --ignore-not-found
```

