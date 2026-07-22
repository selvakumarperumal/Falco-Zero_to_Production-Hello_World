# Generate Default Deny NetworkPolicy

| Property | Value |
|---|---|
| **Type** | Kyverno (GeneratingPolicy) + Falco (Detection) |
| **Kyverno Prevention** | Generates a default-deny ingress/egress NetworkPolicy upon new namespace creation. |
| **Falco Detection** | Alerts on outbound network traffic targeting public IP addresses (ignoring internal pod/node subnets). |

## Description
Automatically generates a default-deny NetworkPolicy for any newly created namespace to ensure zero-trust segmentation. Detects unexpected outbound connections outside internal cluster network ranges at runtime.

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
  # -------------------------------------------------------------------------
  # Original hello-world rules (preserved from existing ConfigMap)
  # -------------------------------------------------------------------------
  hello-world-rules.yaml: |-
    - rule: Unexpected Outbound Connection from Container
      desc: >
        Detects outbound network connections to destinations outside
        the cluster internal network ranges.
      condition: >
        evt.type = connect and evt.dir = <
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
### Kyverno Policy Manifest Explanation
Kyverno generates zero-trust networking templates automatically:
- **`kinds: [Namespace]`**: Fires when a Namespace is created.
- **`generate.kind: NetworkPolicy`**: Creates a NetworkPolicy object.
- **`synchronize: true`**: Syncs policy configuration. If the template changes, Kyverno updates it across namespaces.
- **`data`**: Declares a default-deny policy (empty `podSelector` and both `Ingress` and `Egress` policyTypes).

### Falco Rule Manifest Explanation
The runtime rule detects outbound network traversal:
- **`evt.type = connect and evt.dir = <`**: Fires on completed outbound TCP/UDP connection requests.
- **`fd.typechar = 4`**: Restricts targeting to IPv4 connections.
- **`not fd.sip in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")`**: Ignores cluster private IP blocks. A connection to any public IP fires a `WARNING` alert indicating potential exfiltration.

## How to Test
### Kyverno (Admission Check)
1. Create a namespace:
```bash
kubectl create namespace test-deny-policy
```
2. Check that the NetworkPolicy is automatically created:
```bash
kubectl get netpol -n test-deny-policy
```
3. Clean up:
```bash
kubectl delete namespace test-deny-policy
```

### Falco (Runtime Check)
1. Spin up a container and ping an external server (e.g. 8.8.8.8):
```bash
kubectl run test-outbound-ping --image=alpine --restart=Never -it -- ping -c 1 8.8.8.8
```
2. Check Falco alerts for: `Unexpected Outbound Connection from Container`.
3. Clean up:
```bash
kubectl delete pod test-outbound-ping
```
