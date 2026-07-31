# Disallow NodePort Services

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Enforces that service definitions do not specify `type: NodePort`. |
| **Falco Detection** | Monitors `bind`/`listen` syscalls to detect processes binding to unexpected ports (excluding ports like 80, 443, 8080, etc.). |

## Description
Blocks Services using `type: NodePort` which bypasses Ingress/LoadBalancers and exposes host-level ports. Detects containers binding to unexpected non-standard listening ports at runtime.

### 🛡️ Problem Statement — What Are We Preventing?

NodePort services allocate a port in the range 30000–32767 on **every node** in the cluster, making the service directly reachable from outside the cluster via `<NodeIP>:<NodePort>`. While convenient for quick testing, this creates significant security and operational risks in production:

* **Uncontrolled External Exposure**: NodePort bypasses centralized ingress controllers (NGINX, Traefik, Istio Gateway) that provide TLS termination, rate limiting, WAF protection, and authentication. Traffic arrives directly at the service without any of these security layers.
* **Attack Surface Expansion**: Every NodePort service opens a port on every worker node in the cluster. External port scanners can discover these ports and directly probe the exposed services. In cloud environments, this may inadvertently expose internal services to the public internet if security groups are misconfigured.
* **Network Policy Bypass**: Kubernetes NetworkPolicies operate at the pod/namespace level, but NodePort traffic arrives at the node's network stack before network policies are applied, potentially allowing traffic that should be blocked by zero-trust network segmentation.
* **Port Conflict and Exhaustion**: The NodePort range is limited (2768 ports). In large clusters with many teams, uncontrolled NodePort usage leads to port conflicts and exhaustion, causing deployment failures.
* **Compliance Violations**: Security standards like CIS Kubernetes Benchmark and PCI-DSS recommend against using NodePort for external access, requiring load balancers or ingress controllers that provide centralized access logging and audit trails.

**Kyverno prevents this** by validating that no Service object specifies `type: NodePort`, forcing teams to use `ClusterIP` with Ingress or `LoadBalancer` for controlled external access. **Falco detects** containers binding to unexpected ports at runtime, catching potential backdoor listeners that bypass normal service configuration.


## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: disallow-nodeport-services
  annotations:
    policies.kyverno.io/title: Disallow NodePort Services
    policies.kyverno.io/category: Network Security
    policies.kyverno.io/severity: medium
    policies.kyverno.io/description: >-
      NodePort services expose ports on every cluster node. Use LoadBalancer
      or Ingress instead for controlled external access.
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
        resources: [services]
  validations:
    - message: "NodePort services are not allowed. Use LoadBalancer or ClusterIP."
      expression: >-
        !has(object.spec.type) || object.spec.type != 'NodePort'
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
    - rule: Unexpected Listening Port in Container
      desc: >
        Detects a container process binding to a port outside the expected
        application range (common for backdoors and reverse shells).
      source: syscall
      condition: >
        evt.type in (bind, listen)
        and container
        and fd.sport != 0
        and not fd.sport in (80, 443, 8080, 8443, 3000, 5000, 9090)
        and not k8s.ns.name in (kube-system, kyverno)
      output: >
        Unexpected port binding in container (port=%fd.sport
        command=%proc.cmdline pod=%k8s.pod.name ns=%k8s.ns.name)
      priority: NOTICE
      tags: [kyverno_companion, network, mitre_command_and_control]
```

## Detailed Explanation

### Kyverno CEL Expression Breakdown

```
!has(object.spec.type) || object.spec.type != 'NodePort'
```

This is a notably simple CEL expression compared to pod-level policies:

| CEL Fragment | What It Does | Why It's Needed |
|---|---|---|
| `!has(object.spec.type)` | Returns `true` if the `type` field is absent from the Service spec. | When `spec.type` is omitted, Kubernetes defaults to `ClusterIP` (internal-only). This is safe — the policy should allow it. |
| `\|\|` (OR operator) | If the field is absent, short-circuit to `true` (admitted). Otherwise, check the value. | Handles the common case where services don't explicitly set `type`. |
| `object.spec.type != 'NodePort'` | Returns `true` if the type is anything other than `NodePort`. | Allows `ClusterIP`, `LoadBalancer`, and `ExternalName` — only `NodePort` is blocked. |

> **Why target Services, not Pods:** This is one of the few Kyverno policies that targets `resources: [services]` instead of `resources: [pods]`. NodePort is a Service-level configuration, not a container-level one.

#### CEL Evaluation Trace — ClusterIP Service (Default)

```
Step 1: has(object.spec.type) → false (type field omitted, defaults to ClusterIP)
Step 2: !false = true → SHORT-CIRCUIT → ADMITTED
```

#### CEL Evaluation Trace — NodePort Service

```
Step 1: has(object.spec.type) → true
Step 2: !true = false → evaluate right side
Step 3: object.spec.type = "NodePort" → "NodePort" != "NodePort" → false
Step 4: false || false = false → DENIED
```

---

### Falco Condition Breakdown

```
evt.type in (bind, listen) and container
and fd.sport != 0
and not fd.sport in (80, 443, 8080, 8443, 3000, 5000, 9090)
and not k8s.ns.name in (kube-system, kyverno)
```

| Falco Field | What It Does | Why It's Included |
|---|---|---|
| `evt.type in (bind, listen)` | Matches socket `bind` (assign address to socket) and `listen` (mark socket as passive) syscalls. | These syscalls are the precursors to accepting network connections — any process listening on a port goes through these calls. |
| `container` | Event must originate inside a container. | Host-level network daemons legitimately bind to many ports. |
| `fd.sport != 0` | The source port is non-zero (a port is actually allocated). | Port 0 means "let the kernel choose" — it's used for outbound connections, not servers. |
| `not fd.sport in (80, 443, 8080, 8443, 3000, 5000, 9090)` | Excludes commonly used application ports. | These are standard web server and application ports that are expected. Binding to an unexpected port (e.g., 4444, 1337) suggests a backdoor or reverse shell listener. |
| `not k8s.ns.name in (kube-system, kyverno)` | Excludes system namespaces. | System components bind to various ports as part of normal operation. |

---

### 🔗 Defense-in-Depth: How Kyverno and Falco Work Together

| Layer | When It Acts | What It Catches |
|---|---|---|
| **Kyverno** (Admission) | At Service creation/update | Blocks NodePort Service objects from being created, preventing cluster-wide port exposure. |
| **Falco** (Runtime) | When a process binds to an unexpected port | Detects backdoor listeners and reverse shell servers inside containers, regardless of Service type. |

**Key gap Falco covers:** Kyverno blocks NodePort Services at the API level, but cannot prevent a compromised container from binding to a port directly. An attacker can use `nc -l -p 4444` inside a container to listen for connections without creating any Kubernetes Service. Falco detects this at the syscall level.

### MITRE ATT&CK Mapping

| Tag | Technique | Description |
|---|---|---|
| `mitre_command_and_control` | **T1571 — Non-Standard Port** | Attackers use non-standard ports for C2 channels to avoid detection by port-based firewall rules. |

## Test Scenarios & Manifest Examples

### 1. ✅ PASS Case 1 — Service Type `ClusterIP`
```yaml
apiVersion: v1
kind: Service
metadata:
  name: test-pass-clusterip
  namespace: default
spec:
  type: ClusterIP
  ports:
    - port: 80
      targetPort: 8080
  selector:
    app: web
```
* **Result**: **PASS** — `object.spec.type != 'NodePort'` evaluates to `true`.

---

### 2. ✅ PASS Case 2 — Service Type `LoadBalancer`
```yaml
apiVersion: v1
kind: Service
metadata:
  name: test-pass-lb
  namespace: default
spec:
  type: LoadBalancer
  ports:
    - port: 443
      targetPort: 8443
  selector:
    app: web
```
* **Result**: **PASS** — Service type is `LoadBalancer`, allowed for managed external entry points.

---

### 3. ❌ FAIL Case — Service Type `NodePort`
```yaml
apiVersion: v1
kind: Service
metadata:
  name: test-fail-nodeport
  namespace: default
spec:
  type: NodePort
  ports:
    - port: 80
      nodePort: 30080
  selector:
    app: web
```
* **Result**: **FAIL** — `object.spec.type == 'NodePort'` violates the policy rule.

---

## How to Test

### Kyverno (Admission Control Dry-Run Check)
```bash
# 1. Test PASS case (ClusterIP Service should be allowed)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Service
metadata:
  name: test-pass-svc
  namespace: default
spec:
  type: ClusterIP
  ports:
    - port: 80
  selector:
    app: nginx
EOF

# 2. Test FAIL case (NodePort Service should be denied)
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Service
metadata:
  name: test-fail-svc
  namespace: default
spec:
  type: NodePort
  ports:
    - port: 80
  selector:
    app: nginx
EOF
```

### Falco (Runtime Listening Port Check)
1. Run a container and listen on an unapproved port (outside 80, 443, 8080, 8443, 3000, 5000, 9090):
```bash
kubectl run test-port-bind --image=alpine --restart=Never -it -- nc -l -p 9999
```
2. Verify Falco alerts show: `Unexpected Listening Port in Container`.
3. Clean up:
```bash
kubectl delete pod test-port-bind --ignore-not-found
```

