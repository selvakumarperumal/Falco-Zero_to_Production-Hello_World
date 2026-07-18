# Interactive Shell Spawned in Container

| Property | Value |
|---|---|
| **Type** | Falco (Detection Only) |
| **Kyverno Prevention** | N/A (Admission control cannot prevent execution of commands inside already-running containers). |
| **Falco Detection** | eBPF syscall analysis checking for process execution matches of shell binary names linked to an active TTY/interactive terminal. |

## Description
Detects when an interactive shell (e.g., `bash`, `sh`, `zsh`) is spawned inside a container. This is a crucial runtime indicator of compromise or unauthorized access.

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
    - rule: Interactive Shell Spawned in Container
      desc: >
        Detects an interactive shell (bash, sh, zsh) spawned inside a
        container. This is a common post-exploitation indicator.
      condition: >
        spawned_process and container
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
