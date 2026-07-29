# Interactive Shell Spawned in Container

| Property | Value |
|---|---|
| **Type** | Falco (Detection Only) |
| **Kyverno Prevention** | N/A (Admission control cannot prevent execution of commands inside already-running containers). |
| **Falco Detection** | eBPF syscall analysis checking for process execution matches of shell binary names linked to an active TTY/interactive terminal. |

## Description
Detects when an interactive shell (e.g., `bash`, `sh`, `zsh`) is spawned inside a container. This is a crucial runtime indicator of compromise or unauthorized access.

### 🛡️ Problem Statement — What Are We Preventing?

In production Kubernetes environments, containers should run predefined application processes — not interactive shells. The spawning of an interactive shell inside a container is one of the strongest indicators that an attacker has gained unauthorized access or that an operator is performing risky ad-hoc actions:

* **Post-Exploitation Indicator (MITRE ATT&CK: T1059.004)**: After exploiting a vulnerability (e.g., RCE, SSRF, deserialization flaw) in a containerized application, an attacker's first action is typically to spawn an interactive shell to explore the environment, read configuration files, discover secrets, and plan lateral movement. Detecting this shell spawn is often the earliest possible signal of a container compromise.
* **kubectl exec Abuse**: In organizations without strict RBAC controls, developers or operators may use `kubectl exec -it <pod> -- bash` to access production containers directly. This bypasses change management processes, creates unaudited access, and can introduce configuration drift or accidental damage to running applications.
* **Insider Threat Detection**: Malicious insiders with cluster access may use interactive shells to exfiltrate data, modify application behavior, or install backdoors. Without shell spawn detection, these activities leave no trace in standard application logs.
* **Immutability Violation**: The principle of container immutability dictates that containers should not be modified at runtime. An interactive shell session inherently violates this principle — any changes made during the session (installed packages, modified configs, written files) are untracked and lost on restart, creating unpredictable behavior.
* **Compliance and Audit Requirements**: Security frameworks (SOC2 CC6.1, PCI-DSS Requirement 10, CIS Kubernetes Benchmark 5.6.1) require monitoring and logging of all interactive access to production systems. Without shell detection, organizations cannot demonstrate compliance with access monitoring controls.

**Falco detects this** by monitoring `execve` syscalls inside containers for known shell binaries (`bash`, `sh`, `zsh`, `ksh`, `csh`, `fish`, `dash`) that are connected to an interactive terminal (`proc.tty != 0`), firing a `WARNING` alert that enables security teams to investigate and respond immediately.


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
    - rule: Interactive Shell Spawned in Container
      desc: >
        Detects an interactive shell (bash, sh, zsh) spawned inside a
        container. This is a common post-exploitation indicator.
      source: syscall
      condition: >
        evt.type in (execve, execveat) and evt.failed = false and container
        and proc.name in (bash, sh, zsh, ksh, csh, fish, dash)
        and proc.tty != 0
        and not k8s.ns.name in (kube-system, kyverno)
      output: >
        Interactive shell spawned in container (user=%user.name
        shell=%proc.name command=%proc.cmdline pod=%k8s.pod.name
        ns=%k8s.ns.name image=%container.image.repository)
      priority: WARNING
      tags: [runtime_only, shell, mitre_execution]
```

## Detailed Explanation
### Falco Rule Manifest Explanation
This is a detection-only control monitoring user session spawn:
- **`spawned_process and container`**: Listens to new processes inside container boundaries.
- **`proc.name in (bash, sh, zsh, ksh, csh, fish, dash)`**: Monitors common shells.
- **`proc.tty != 0`**: Ensures the shell is linked to an interactive terminal session (e.g. `kubectl exec -it`). This helps differentiate an interactive session from script/system processes running non-interactively (which have TTY = 0).
- **`not k8s.ns.name in (kube-system, kyverno)`**: Exempts system namespaces to avoid alerts on cluster administration operations.

## How to Test
1. Run any simple container:
```bash
kubectl run test-shell --image=nginx --restart=Never
```
2. Execute an interactive shell session into the running pod:
```bash
kubectl exec -it test-shell -- sh
```
3. Run a couple of quick commands in the shell, exit, and verify that Falco logs: `Interactive Shell Spawned in Container`.
4. Clean up:
```bash
kubectl delete pod test-shell
```
