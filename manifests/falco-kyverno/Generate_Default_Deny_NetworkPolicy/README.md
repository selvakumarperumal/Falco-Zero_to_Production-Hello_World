# Generate Default Deny NetworkPolicy

| Property | Value |
|---|---|
| **Type** | Kyverno (GeneratingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Generates a default-deny ingress/egress NetworkPolicy upon new namespace creation. |
| **Falco Detection** | Alerts on outbound network traffic targeting public IP addresses (ignoring internal pod/node subnets). |

## Description
Automatically generates a default-deny NetworkPolicy for any newly created namespace to ensure zero-trust segmentation. Detects unexpected outbound connections outside internal cluster network ranges at runtime.

### 🛡️ Problem Statement — What Are We Preventing?

By default, Kubernetes networking is **fully permissive** — every pod can communicate with every other pod in the cluster, regardless of namespace, with no restrictions on ingress or egress traffic. This flat network model is one of the most exploited attack surfaces in Kubernetes:

* **Unrestricted Lateral Movement (MITRE ATT&CK: T1021)**: When an attacker compromises a single pod, the default-allow network model lets them reach every other pod in the cluster. They can scan for databases, API services, admin interfaces, and other high-value targets across all namespaces without any network-level barrier.
* **Data Exfiltration**: Without egress restrictions, a compromised pod can freely connect to external servers to exfiltrate stolen data, download malicious payloads, or establish command-and-control (C2) channels. The attacker can stream sensitive data out of the cluster with zero resistance.
* **Blast Radius Amplification**: A single vulnerable microservice can become the entry point for a cluster-wide compromise. Without network segmentation, the blast radius of any security incident extends to every pod and service in the cluster.
* **Compliance Violations**: Frameworks like PCI-DSS (Requirement 7), NIST SP 800-190, and CIS Kubernetes Benchmark require network segmentation and default-deny policies. Operating without them can result in audit failures and regulatory penalties.
* **Human Error**: Relying on developers to manually create NetworkPolicies in every namespace is unreliable. New namespaces created for testing, CI/CD pipelines, or feature branches are frequently left without any network restrictions, creating security gaps.

**Kyverno prevents this** by automatically generating a default-deny NetworkPolicy (blocking both ingress and egress) in every newly created namespace, establishing a zero-trust network baseline. Teams must then explicitly create allow policies for their required communication paths. **Falco detects** unexpected outbound connections to public IP addresses at runtime, alerting on potential exfiltration or C2 activity that bypasses network policies.


## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: GeneratingPolicy
metadata:
  name: generate-default-deny-netpol
  annotations:
    policies.kyverno.io/title: Generate Default-Deny Network Policy
    policies.kyverno.io/category: Network Security
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      Automatically creates a default-deny NetworkPolicy in every new
      namespace to enforce zero-trust networking.
  labels:
    app.kubernetes.io/part-of: kyverno-falco-policies
spec:
  matchConstraints:
    resourceRules:
      - apiGroups: ['']
        apiVersions: ['v1']
        operations: [CREATE]
        resources: [namespaces]
  variables:
    - name: nsName
      expression: 'object.metadata.name'
    - name: downstream
      expression: >-
        [
          {
            "apiVersion": dyn("networking.k8s.io/v1"),
            "kind": dyn("NetworkPolicy"),
            "metadata": dyn({
              "name": "default-deny-all",
              "namespace": string(variables.nsName)
            }),
            "spec": dyn({
              "podSelector": dyn({}),
              "policyTypes": dyn(["Ingress", "Egress"])
            })
          }
        ]
  generate:
    - expression: generator.Apply(variables.nsName, variables.downstream)
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
    - rule: Unexpected Outbound Connection from Container
      desc: >
        Detects outbound network connections to destinations outside
        the cluster internal network ranges.
      source: syscall
      condition: >
        evt.type = connect
        and container
        and fd.typechar = 4
        and fd.ip != "0.0.0.0"
        and not fd.sip in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        and not k8s.ns.name in (kube-system, kyverno)
      output: >
        Unexpected outbound connection (connection=%fd.name
        command=%proc.cmdline pod=%k8s.pod.name ns=%k8s.ns.name)
      priority: WARNING
      tags: [kyverno_companion, network, mitre_exfiltration]
```

## Detailed Explanation
#### Truth Table — Kyverno Generator Evaluation

| Target Namespace Event | Namespace Excluded (`kube-system` / `kyverno`) | Generator Result |
|---|---|---|
| `CREATE` | `true` (`kube-system`) | Skip generation |
| `CREATE` | `false` (`prod-app`) | **GENERATE** (`default-deny` NetworkPolicy) |

#### Truth Table — Falco Runtime Detections

| `evt.type` | `container` | Destination IP (`fd.sip`) | Namespace Excluded | Falco Alert Result |
|---|---|---|---|---|
| `connect` | `true` | `10.0.1.5` (RFC1918 Private IP) | `false` | No Alert |
| `connect` | `true` | `1.1.1.1` (Public External IP) | `true` (`kube-system`) | No Alert |
| `connect` | `true` | `203.0.113.5` (Public External IP) | `false` (`default`) | **ALERT FIRED (WARNING)** |



### Kyverno CEL / GeneratingPolicy Breakdown

```yaml
variables:
  - name: nsName
    expression: 'object.metadata.name'
  - name: downstream
    expression: >-
      [
        {
          "apiVersion": dyn("networking.k8s.io/v1"),
          "kind": dyn("NetworkPolicy"),
          "metadata": dyn({
            "name": "default-deny-all",
            "namespace": string(variables.nsName)
          }),
          "spec": dyn({
            "podSelector": dyn({}),
            "policyTypes": dyn(["Ingress", "Egress"])
          })
        }
      ]
generate:
  - expression: generator.Apply(variables.nsName, variables.downstream)
```

| CEL Fragment | What It Does | Why It's Needed |
|---|---|---|
| `object.metadata.name` | Extracts the name of the newly created Namespace trigger object. | Dynamically scopes downstream generated NetworkPolicy to the target namespace. |
| `dyn(...)` | Dynamic type wrapper for CEL expressions constructing Kubernetes resource manifests. | Required when building unstructured map structures inside CEL generator policies. |
| `"podSelector": dyn({})` | Empty pod selector `{}`. | Selects **all** pods in the target namespace. |
| `"policyTypes": dyn(["Ingress", "Egress"])` | Enables both Ingress and Egress policy enforcement. | Blocks all unexplicitly allowed inbound and outbound network traffic (zero-trust baseline). |
| `generator.Apply(...)` | Kyverno CEL generator function to create/reconcile downstream resource. | Automatically creates `NetworkPolicy/default-deny-all` in target namespace and keeps it synced. |

---

### Falco Condition Breakdown

```
evt.type = connect and container and fd.typechar = 4
and fd.ip != "0.0.0.0"
and not fd.sip in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
and not k8s.ns.name in (kube-system, kyverno)
```

| Falco Field | What It Does | Why It's Included |
|---|---|---|
| `evt.type = connect` | Matches outgoing network socket connection requests. | Detects active outbound network connections. |
| `container` | Ensures event originates inside a container. | Excludes host node network connections. |
| `fd.typechar = 4` | Restricts check to IPv4 socket descriptors. | Filters for standard IPv4 network connections. |
| `fd.ip != "0.0.0.0"` | Ignores wildcard listen/bind IPs. | Focuses on active target connection addresses. |
| `not fd.sip in ("10.0.0.0/8", ...)` | Excludes internal cluster private IP CIDR ranges. | Connections to public external IPs trigger an alert. |
| `not k8s.ns.name in (...)` | Excludes system control plane namespaces. | System pods need external connectivity (e.g., API calls, telemetry). |

---

### 🔗 Defense-in-Depth: How Kyverno and Falco Work Together

| Layer | When It Acts | What It Catches |
|---|---|---|
| **Kyverno** (Admission/Generation) | At Namespace creation | Automatically generates a default-deny NetworkPolicy in every new namespace to enforce zero-trust networking. |
| **Falco** (Runtime) | When a network connection is initiated | Detects unexpected outbound connections to external public IPs, providing runtime visibility into network exfiltration. |

### MITRE ATT&CK Mapping

| Tag | Technique | Description |
|---|---|---|
| `mitre_exfiltration` | **T1041 — Exfiltration Over C2 Channel** | Default-deny NetworkPolicies prevent unauthorized egress, while Falco alerts on external network connections. |

## Test Scenarios & Manifest Examples

### 1. ✅ TRIGGER EVENT — New Namespace Creation
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: test-zero-trust-ns
```
* **Result**: **GENERATED** — Kyverno automatically generates `NetworkPolicy` named `default-deny-all` in `test-zero-trust-ns`.

---

### 2. 📋 GENERATED RESOURCE SPECIFICATION — `default-deny-all`
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: test-zero-trust-ns
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```
* **Result**: **ENFORCED** — All pods in `test-zero-trust-ns` have both ingress and egress blocked by default until explicit allow rules are created.

---

## How to Test

### Kyverno (Generation Check)
1. Create a new namespace:
```bash
kubectl create namespace test-deny-policy
```
2. Inspect automatically generated NetworkPolicy:
```bash
kubectl get netpol default-deny-all -n test-deny-policy -o yaml
```

### Falco (Runtime Outbound Connection Check)
1. Spin up a container and connect to a public external IP (e.g. 8.8.8.8):
```bash
kubectl run test-outbound-ping --image=alpine --restart=Never -it -- ping -c 1 8.8.8.8
```
2. Verify Falco logs warning alert: `Unexpected Outbound Connection from Container`.
3. Clean up:
```bash
kubectl delete namespace test-deny-policy --ignore-not-found
kubectl delete pod test-outbound-ping --ignore-not-found
```

