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

### Falco Condition Breakdown

```yaml
condition: >
  evt.type in (execve, execveat) and evt.failed = false and container
  and (proc.name in (nc, ncat, netcat, nmap, socat)
    or (proc.name = "bash" and proc.cmdline contains "/dev/tcp/")
    or (proc.name = "python" and proc.cmdline contains "socket")
    or (proc.name = "python3" and proc.cmdline contains "socket")
    or (proc.name = "perl" and proc.cmdline contains "socket")
    or (proc.name = "ruby" and proc.cmdline contains "TCPSocket")
    or (proc.name = "php" and proc.cmdline contains "fsockopen"))
```

| Falco Field | What It Does | Why It's Included |
|---|---|---|
| `evt.type in (execve, execveat)` | Intercepts process execution syscalls. | Triggers check when a process starts inside container. |
| `evt.failed = false` | Filters for successful executions. | Ignores failed process executions. |
| `container` | Restricts check to container processes. | Ignores host system network utilities. |
| `proc.name in (nc, ncat, netcat, nmap, socat)` | Matches network relay and raw socket tool binary names. | Detects execution of tools commonly used for reverse shell connections. |
| `proc.name = "bash" and ... "/dev/tcp/"` | Detects native Bash pseudo-device TCP socket redirections. | Identifies bash-based reverse shell one-liners (`bash -i >& /dev/tcp/...`). |
| `proc.name in (python, python3, perl, ruby, php) and ...` | Detects socket opening commands executed via scripting language interpreters. | Identifies script-based reverse shells (e.g. Python `socket.socket()`, Perl/Ruby/PHP socket one-liners). |

---

### MITRE ATT&CK Mapping

| Tag | Technique | Description |
|---|---|---|
| `mitre_command_and_control` | **T1059 — Command and Scripting Interpreter** / **T1095 — Non-Application Layer Protocol** | Reverse shells establish an outbound command and control channel from the compromised container back to the attacker. |

## Test Scenarios & Manifest Examples

### 1. 🚨 RUNTIME ALERT CASE 1 — Netcat Execution (`nc`)
```bash
# Executing netcat binary inside container
kubectl run test-nc-shell --image=alpine --restart=Never -it -- nc -h
```
* **Result**: **ALERT (CRITICAL)** — `proc.name = "nc"` matches rule condition. Falco triggers `Possible Reverse Shell Detected`.

---

### 2. 🚨 RUNTIME ALERT CASE 2 — Python Socket Creation (`python3 -c "import socket..."`)
```bash
# Simulating a python reverse shell one-liner
kubectl run test-py-shell --image=python:3.11-slim --restart=Never -- python3 -c "import socket; print('socket test')"
```
* **Result**: **ALERT (CRITICAL)** — `proc.name = "python3"` and `proc.cmdline contains "socket"`.

---

### 3. 🛡️ NORMAL OPERATION — Standard Web Application HTTP Client
```bash
# Legitimate HTTP requests using curl or python requests without raw socket construction
kubectl run test-curl --image=curlimages/curl --restart=Never -- curl https://example.com
```
* **Result**: **NO ALERT** — Process name `curl` does not match reverse shell tools or socket expressions.

---

## How to Test

### Falco (Runtime Reverse Shell Check)
1. Run a container and execute netcat command structure:
```bash
kubectl run test-rev-shell --image=alpine --restart=Never -it -- nc -h
```

2. Verify Falco triggers a critical alert: `Possible Reverse Shell Detected`:
```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco | grep "Possible reverse shell detected"
```

3. Clean up:
```bash
kubectl delete pod test-rev-shell test-nc-shell test-py-shell test-curl --ignore-not-found
```

