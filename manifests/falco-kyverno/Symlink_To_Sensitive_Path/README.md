# Symlink Created to Sensitive Path

| Property | Value |
|---|---|
| **Type** | Falco (Detection Only) |
| **Kyverno Prevention** | N/A (Runtime action). |
| **Falco Detection** | Monitors symlink syscalls aiming at system path patterns. |

## Description
Detects creation of symlinks pointing to host or container-sensitive paths (`/etc/`, `/proc/`, `/sys/`, `/var/run/`). Useful for capturing symlink-based path traversal exploits (e.g. CVE-2021-25741).

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
    - rule: Symlink Created to Sensitive Path
      desc: >
        Detects creation of symbolic links pointing to sensitive paths,
        which is a common container escape technique (CVE-2021-25741).
      condition: >
        evt.type in (symlink, symlinkat) and evt.dir = <
        and container
        and (evt.arg.target startswith "/etc/"
          or evt.arg.target startswith "/proc/"
          or evt.arg.target startswith "/sys/"
          or evt.arg.target startswith "/var/run/")
      output: >
        Symlink to sensitive path created (target=%evt.arg.target
        link=%fd.name command=%proc.cmdline pod=%k8s.pod.name
        ns=%k8s.ns.name)
      priority: CRITICAL
      tags: [runtime_only, symlink_attack, mitre_privilege_escalation]
```

## Detailed Explanation
### Falco Rule Manifest Explanation
This rule detects attempts to bypass directory boundaries via symlinks:
- **`evt.type in (symlink, symlinkat)`**: Focuses specifically on symbolic link creation syscalls.
- **`evt.arg.target startswith "/etc/"` or `/proc/` or `/sys/` or `/var/run/`**: Inspects the symlink target argument. If a link points to these core OS/orchestration directories, Falco triggers a `CRITICAL` alert indicating a potential breakout exploit.

## How to Test
1. Run a temporary container and generate a symlink pointing to `/etc/`:
```bash
kubectl run test-symlink-creation --image=alpine --restart=Never -it -- ln -s /etc/ /tmp/test-etc
```
2. Verify Falco triggers critical alert: `Symlink Created to Sensitive Path`.
3. Clean up:
```bash
kubectl delete pod test-symlink-creation
```
