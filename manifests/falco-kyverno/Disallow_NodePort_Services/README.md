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
### Kyverno Policy Manifest Explanation
The Kyverno configuration protects node-level network exposure:
- **`kinds: [Service]`**: Applies only to Kubernetes Service objects.
- **`spec.type: "!NodePort"`**: Enforces that the service type must NOT be set to NodePort (only ClusterIP or LoadBalancer are permitted).

### Falco Rule Manifest Explanation
The runtime rule acts as a fallback for unauthorized reverse shell/backdoor listeners:
- **`evt.type in (bind, listen)`**: Matches socket bind or listen syscall completions.
- **`fd.sport != 0`**: Ensures a source port is allocated.
- **`not fd.sport in (80, 443, 8080, 8443, 3000, 5000, 9090)`**: Lists approved port exemptions. If a containerized process attempts to open a server socket on any other port, it triggers a `NOTICE` alert.

## How to Test
### Kyverno (Admission Check)
Try to deploy a service using NodePort (should be blocked):
```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: test-nodeport
spec:
  type: NodePort
  ports:
  - port: 80
  selector:
    app: nginx
EOF
```

### Falco (Runtime Check)
1. Run a container and listen on an unapproved port:
```bash
kubectl run test-port-bind --image=alpine --restart=Never -it -- nc -l -p 9999
```
2. Verify Falco alerts show: `Unexpected Listening Port in Container`.
