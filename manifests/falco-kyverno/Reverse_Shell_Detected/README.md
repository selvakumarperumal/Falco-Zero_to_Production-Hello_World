# Reverse Shell Detected in Container

| Property | Value |
|---|---|
| **Type** | Falco (Detection Only) |
| **Kyverno Prevention** | N/A (Runtime action). |
| **Falco Detection** | Identifies shell redirections or scripting sockets attempting outbound terminal control. |

## Description
Detects processes commonly used to spawn reverse shell connections (e.g. netcat redirects, socket creation in Python, Perl, Ruby, PHP).

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
    - rule: Reverse Shell Detected in Container
      desc: >

      source: syscall
        Detects processes commonly used to establish reverse shells,
        including netcat, bash redirections, and scripting language
        one-liners.
      condition: >
        spawned_process and container
        and (proc.name in (nc, ncat, netcat, nmap, socat)
          or (proc.name = "bash" and proc.cmdline contains "/dev/tcp/")
          or (proc.name = "python" and proc.cmdline contains "socket")
          or (proc.name = "python3" and proc.cmdline contains "socket")
          or (proc.name = "perl" and proc.cmdline contains "socket")
          or (proc.name = "ruby" and proc.cmdline contains "TCPSocket")
          or (proc.name = "php" and proc.cmdline contains "fsockopen"))
      output: >
        Possible reverse shell detected (command=%proc.cmdline
        pod=%k8s.pod.name ns=%k8s.ns.name
        image=%container.image.repository user=%user.name)
      priority: CRITICAL
      tags: [runtime_only, reverse_shell, mitre_command_and_control]
```

## Detailed Explanation
### Falco Rule Manifest Explanation
This rule detects attempts to establish interactive terminal control:
- **`spawned_process and container`**: Listens for process execution inside a container.
- **`proc.name in (nc, ncat, netcat, nmap, socat)`**: Tracks execution of network redirectors.
- **`proc.cmdline contains "/dev/tcp/"`**: Detects bash socket redirectors.
- **`proc.cmdline contains "socket"` / `"TCPSocket"` / `"fsockopen"`**: Detects socket creation one-liners in common scripting languages (Python, Perl, Ruby, PHP). Any match triggers a `CRITICAL` alert.

## How to Test
1. Run a container and execute a netcat command structure:
```bash
kubectl run test-rev-shell --image=alpine --restart=Never -it -- nc -h
```
2. Verify Falco triggers a critical alert: `Possible Reverse Shell Detected`.
3. Clean up:
```bash
kubectl delete pod test-rev-shell
```
