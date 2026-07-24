# Disallow NodePort Services

| Property | Value |
|---|---|
| **Type** | Kyverno (ValidatingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Enforces that service definitions do not specify `type: NodePort`. |
| **Falco Detection** | Monitors `bind`/`listen` syscalls to detect processes binding to unexpected ports (excluding ports like 80, 443, 8080, etc.). |

## Description
Blocks Services using `type: NodePort` which bypasses Ingress/LoadBalancers and exposes host-level ports. Detects containers binding to unexpected non-standard listening ports at runtime.

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

      source: syscall
        Detects a container process binding to a port outside the expected
        application range (common for backdoors and reverse shells).
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
