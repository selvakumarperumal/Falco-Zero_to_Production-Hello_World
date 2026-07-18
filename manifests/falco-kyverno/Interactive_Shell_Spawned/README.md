# Interactive Shell Spawned in Container

| Property | Value |
|---|---|
| **Type** | Falco (Detection Only) |
| **Kyverno Prevention** | N/A (Admission control cannot prevent execution of commands inside already-running containers). |
| **Falco Detection** | eBPF syscall analysis checking for process execution matches of shell binary names linked to an active TTY/interactive terminal. |

## Description
Detects when an interactive shell (e.g., `bash`, `sh`, `zsh`) is spawned inside a container. This is a crucial runtime indicator of compromise or unauthorized access.

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
