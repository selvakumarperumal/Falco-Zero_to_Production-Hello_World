# Disallow Default Service Account Token

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Validates that pods using the default service account explicitly turn off token automounting. |
| **Falco Detection** | Detects open/read syscalls targeting files under `/var/run/secrets/kubernetes.io/serviceaccount` by non-system processes. |

## Description
Enforces setting `automountServiceAccountToken: false` on pods utilizing the `default` service account to prevent default service account token mounting. Simultaneously detects runtime access to service account token files.

### 🛡️ Problem Statement — What Are We Preventing?

By default, Kubernetes automatically mounts a service account token into every pod at `/var/run/secrets/kubernetes.io/serviceaccount/token`. When a pod uses the `default` service account (which happens when no explicit SA is specified), this token grants the pod credentials to authenticate against the Kubernetes API server. This is a critical attack vector:

* **Kubernetes API Abuse (MITRE ATT&CK: T1552.007)**: If an attacker compromises an application container (e.g., via an RCE vulnerability), the auto-mounted token gives them immediate, authenticated access to the Kubernetes API. They can list pods, secrets, services, and config maps — and depending on RBAC misconfigurations, potentially create or modify resources.
* **Lateral Movement**: With a valid service account token, an attacker can enumerate other namespaces, discover services, and pivot to other workloads. The `default` SA token is especially dangerous because it exists in every namespace and is often overlooked in RBAC hardening efforts.
* **Secret Exfiltration**: In clusters with overly permissive RBAC, the `default` service account may have implicit read access to secrets. An attacker with the token can run `kubectl get secrets` from within the container to exfiltrate database passwords, API keys, and TLS certificates.
* **Persistent Backdoor Installation**: With write access via the API, attackers can create new pods, deploy CronJobs, or modify existing workloads to establish persistence — all using the auto-mounted token.
* **Unnecessary Blast Radius**: Most application pods never need to interact with the Kubernetes API. Mounting a token "just in case" violates the principle of least privilege and expands the blast radius of any container compromise.

**Kyverno prevents this** by validating that any pod using the `default` service account explicitly sets `automountServiceAccountToken: false`. **Falco detects** runtime access to the token file at `/var/run/secrets/kubernetes.io/serviceaccount/`, alerting security teams when any process attempts to read the mounted credentials.


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
#### Truth Table — Kyverno CEL Evaluation

| `has(automountServiceAccountToken)` | `automountServiceAccountToken` Value | `has(...) && ==true` | `!(...)` → Clause Result | Policy Decision |
|---|---|---|---|---|
| `false` (not set) | — | `false` | `true` | **PASS** |
| `true` | `false` | `false` | `true` | **PASS** |
| `true` | `true` | `true` | `false` | **FAIL** |

#### Truth Table — Falco Runtime Detections

| `evt.type` | `container` | `fd.name` Path | Falco Alert Result |
|---|---|---|---|
| `open` / `openat` | `false` (host) | `/var/run/secrets/.../token` | No Alert |
| `open` / `openat` | `true` | `/etc/config` | No Alert |
| `open` / `openat` | `true` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | **ALERT FIRED (WARNING)** |



### Kyverno CEL Expression Breakdown

```
(!has(object.spec.serviceAccountName) || object.spec.serviceAccountName == 'default') ?
(has(object.spec.automountServiceAccountToken) && object.spec.automountServiceAccountToken == false) : true
```

The policy uses a CEL **ternary operator** (`condition ? true_branch : false_branch`):

| CEL Fragment | What It Does | Why It's Needed |
|---|---|---|
| `!has(object.spec.serviceAccountName)` | Checks if `serviceAccountName` is absent. | Pods without an explicit SA name automatically default to the `default` SA. |
| `object.spec.serviceAccountName == 'default'` | Checks if SA is explicitly set to `'default'`. | Identifies pods assigned to the default service account. |
| `(!has(...) \|\| ... == 'default') ?` | Condition: Is this pod using the default ServiceAccount? | If `true`, evaluate the automount requirement (true branch). If `false`, skip check (returns `true` immediately). |
| `has(object.spec.automountServiceAccountToken)` | Checks if `automountServiceAccountToken` is set on the Pod spec. | Verifies the field exists before comparing value. |
| `object.spec.automountServiceAccountToken == false` | Checks that token automounting is explicitly disabled. | Ensures default SA pods opt out of token injection. |
| `: true` | False branch of ternary expression. | Custom ServiceAccounts are exempt from this policy rule. |

---

### Falco Condition Breakdown

```
evt.type in (open, openat, openat2) and container
and fd.name contains "/var/run/secrets/kubernetes.io/serviceaccount"
and not k8s.ns.name in (kube-system, kyverno)
and not proc.name in (pause, tini)
```

| Falco Field | What It Does | Why It's Included |
|---|---|---|
| `evt.type in (open, openat, openat2)` | Matches file open syscalls. | Detects when a process opens the mounted service account token file. |
| `container` | Scopes detection to container processes. | Filters out host-level processes. |
| `fd.name contains "/var/run/secrets/kubernetes.io/serviceaccount"` | Matches the standard Kubernetes service account token mount path. | Identifies attempts to read SA token, CA cert, or namespace files. |
| `not k8s.ns.name in (kube-system, kyverno)` | Excludes cluster management namespaces. | System pods legitimately read their SA tokens to communicate with the API server. |
| `not proc.name in (pause, tini)` | Excludes container init processes/reapers. | Ignores container runtime setup processes. |

---

### 🔗 Defense-in-Depth: How Kyverno and Falco Work Together

| Layer | When It Acts | What It Catches |
|---|---|---|
| **Kyverno** (Admission) | At pod creation/update | Prevents default SA pods from mounting service account tokens at admission time. |
| **Falco** (Runtime) | When token file is opened | Detects credential access attempts if a container process opens the SA token path at runtime. |

### MITRE ATT&CK Mapping

| Tag | Technique | Description |
|---|---|---|
| `mitre_credential_access` | **T1552.007 — Unsecured Credentials: Container API Tokens** | Attackers read mounted service account tokens to authenticate to the Kubernetes API server for lateral movement. |

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

