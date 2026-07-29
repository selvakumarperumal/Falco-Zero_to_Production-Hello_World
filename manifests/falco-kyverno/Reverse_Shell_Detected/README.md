# Reverse Shell Detected in Container

| Property | Value |
|---|---|
| **Type** | Falco (Detection Only) |
| **Kyverno Prevention** | N/A (Runtime action). |
| **Falco Detection** | Identifies shell redirections or scripting sockets attempting outbound terminal control. |

## Description
Detects processes commonly used to spawn reverse shell connections (e.g. netcat redirects, socket creation in Python, Perl, Ruby, PHP).

### 🛡️ Problem Statement — What Are We Preventing?

A reverse shell is the most dangerous post-exploitation technique in containerized environments. Unlike a regular shell, a reverse shell initiates an **outbound** connection from the compromised container to an attacker-controlled server, bypassing firewalls and network policies that typically block inbound connections:

* **Command and Control Channel (MITRE ATT&CK: T1059)**: A reverse shell gives an attacker a fully interactive terminal session inside the compromised container, allowing them to execute arbitrary commands, explore the environment, read secrets, and pivot to other systems — all in real-time from their own machine.
* **Firewall and Network Policy Bypass**: Reverse shells work by creating outbound connections (typically over TCP ports 80, 443, or 8080 to blend with legitimate traffic). Since most firewall rules and Kubernetes NetworkPolicies allow outbound traffic by default, reverse shells bypass perimeter security controls that would block inbound connections.
* **Data Exfiltration**: Once a reverse shell is established, attackers can exfiltrate any data accessible to the container — application databases, API keys, environment variables, mounted secrets, service account tokens — streaming it directly to their external server.
* **Lateral Movement Launchpad**: From a reverse shell session, attackers can use the compromised container as a pivot point to scan the internal cluster network, exploit adjacent services, and move laterally to other namespaces and workloads — especially if the container has network access and a service account token.
* **Persistence**: Sophisticated attackers use reverse shells to install persistent backdoors (cron jobs, modified images, additional deployments) before closing the initial shell, ensuring continued access even if the initial vulnerability is patched.

**Falco detects this** by monitoring `execve` syscalls for known reverse shell tools (`nc`, `ncat`, `netcat`, `nmap`, `socat`) and scripting language patterns that create socket connections (`bash /dev/tcp/`, Python `socket`, Perl `socket`, Ruby `TCPSocket`, PHP `fsockopen`), firing a `CRITICAL` alert for immediate incident response.


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
        Detects processes commonly used to establish reverse shells,
        including netcat, bash redirections, and scripting language
        one-liners.
      source: syscall
      condition: >
        evt.type in (execve, execveat) and evt.failed = false and container
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
