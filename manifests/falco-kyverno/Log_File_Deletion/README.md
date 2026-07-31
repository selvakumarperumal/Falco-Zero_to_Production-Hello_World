# Log File Deletion in Container

| Property | Value |
|---|---|
| **Type** | Falco (Detection Only) |
| **Kyverno Prevention** | N/A (Runtime file manipulation check). |
| **Falco Detection** | Monitors file-related syscalls like `unlink`, `unlinkat`, `rename`, `renameat` matching paths to log signatures. |

## Description
Detects deletion or renaming of log files (`/var/log/*`, `*.log`, `syslog`, `history`) inside a container, indicating attempts to cover tracks or delete audit records.

### 🛡️ Problem Statement — What Are We Preventing?

Log files are the primary evidence source during security incident investigations. When an attacker gains access to a container, one of their first objectives is to destroy or tamper with logs to eliminate traces of their activity. This anti-forensics technique is a critical defense evasion tactic:

* **Evidence Destruction (MITRE ATT&CK: T1070.002)**: Attackers routinely delete `/var/log/*` files, `.bash_history`, `auth.log`, and `syslog` to erase records of their commands, login attempts, and privilege escalation activities. Without detection of log deletion, the security team may never know that a compromise occurred.
* **Compliance Violations**: Regulatory frameworks (PCI-DSS Requirement 10.7, HIPAA §164.312(b), SOC2 CC7.2) require that audit logs be preserved and protected from tampering. Log deletion inside containers represents a direct compliance violation that can result in regulatory penalties.
* **Blind Incident Response**: When logs are deleted before they can be forwarded to a centralized logging system (e.g., Elasticsearch, Splunk, Loki), incident responders lose visibility into what happened inside the container. This creates a forensic gap that prevents accurate root cause analysis, blast radius assessment, and timeline reconstruction.
* **History File Tampering**: Shell history files (`.bash_history`, `.zsh_history`) contain a sequential record of every command an attacker executed. Deleting these files is a standard post-exploitation cleanup step that removes the most direct evidence of attacker activity.
* **Lateral Movement Cover-Up**: Attackers who pivot from one container to another often clean up logs in each compromised container to prevent security teams from mapping the full attack path across the cluster.

**Falco detects this** by monitoring file-related syscalls (`unlink`, `unlinkat`, `rename`, `renameat`) targeting log file paths and patterns, firing an `ERROR` alert when log files are deleted or renamed — excluding legitimate processes like `logrotate` and `journald` that perform authorized log management.


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
    - rule: Log File Deletion in Container
      desc: >
        Detects deletion of log files inside a container, which may
        indicate an attacker covering their tracks.
      source: syscall
      condition: >
        evt.type in (unlink, unlinkat, rename, renameat)
        and container
        and (fd.name startswith "/var/log/"
          or fd.name endswith ".log"
          or fd.name contains "syslog"
          or fd.name contains "auth.log"
          or fd.name contains "history")
        and not proc.name in (logrotate, journald)
      output: >
        Log file deleted in container (file=%fd.name command=%proc.cmdline
        pod=%k8s.pod.name ns=%k8s.ns.name user=%user.name)
      priority: ERROR
      tags: [runtime_only, log_tampering, mitre_defense_evasion]
```

## Detailed Explanation
#### Truth Table — Falco Runtime Detections

| `evt.type` | `container` | Target `fd.name` Pattern | Process Excluded | Falco Alert Result |
|---|---|---|---|---|
| `unlink` | `true` | `/tmp/file.txt` | `false` | No Alert |
| `unlink` | `true` | `/var/log/app.log` | `true` (`logrotate`) | No Alert |
| `unlink` / `rename` | `true` | `/var/log/syslog` / `.log` / `auth.log` | `false` (`rm` / `sh`) | **ALERT FIRED (WARNING)** |



### Falco Condition Breakdown

```yaml
condition: >
  evt.type in (unlink, unlinkat, rename, renameat)
  and container
  and (fd.name startswith "/var/log/"
    or fd.name endswith ".log"
    or fd.name contains "syslog"
    or fd.name contains "auth.log"
    or fd.name contains "history")
  and not proc.name in (logrotate, journald)
```

| Falco Field | What It Does | Why It's Included |
|---|---|---|
| `evt.type in (unlink, unlinkat, rename, renameat)` | Intercepts file deletion (`unlink`/`unlinkat`) and file moving/renaming (`rename`/`renameat`) syscalls. | Detects file removal or masking operations. |
| `container` | Restricts check to container processes. | Ignores host system log operations. |
| `fd.name startswith "/var/log/"` | Checks if target file is located inside standard log directory. | Catches deletion of application and system log files. |
| `fd.name endswith ".log"` | Checks for `.log` file extensions anywhere on container filesystem. | Catches log file deletion outside `/var/log`. |
| `fd.name contains "syslog"` / `"auth.log"` | Targets critical system audit logs. | Detects destruction of authentication logs. |
| `fd.name contains "history"` | Targets shell history files (e.g. `.bash_history`). | Detects anti-forensics cleanup of command history. |
| `not proc.name in (logrotate, journald)` | Excludes legitimate log maintenance utilities. | Prevents false alerts from authorized log rotation. |

---

### MITRE ATT&CK Mapping

| Tag | Technique | Description |
|---|---|---|
| `mitre_defense_evasion` | **T1070.002 — Indicator Removal: Clear Linux or Mac System Logs** | Attackers delete log files and shell history to cover their tracks and hinder post-incident forensic investigations. |

## Test Scenarios & Manifest Examples

### 1. 🚨 RUNTIME ALERT CASE — Log File Unlink (`rm /var/log/app.log`)
```bash
# Simulating attacker unlinking log file inside container
kubectl run test-log-unlink --image=alpine --restart=Never -- sh -c "touch /var/log/audit.log && rm /var/log/audit.log"
```
* **Result**: **ALERT (ERROR)** — `evt.type = unlink` on `/var/log/audit.log` matches rule. Falco triggers `Log File Deletion in Container`.

---

### 2. 🛡️ EXEMPT CASE — Authorized Log Maintenance (`logrotate`)
```bash
# Legitimate log rotation by safe-listed daemon process
# proc.name in (logrotate, journald)
```
* **Result**: **NO ALERT** — Excluded by condition `not proc.name in (logrotate, journald)`.

---

## How to Test

### Falco (Runtime File Tampering Check)
1. Run temporary pod performing file creation and deletion under `/var/log`:
```bash
kubectl run test-log-del --image=alpine --restart=Never -it -- sh -c "touch /var/log/test.log && rm /var/log/test.log"
```

2. Check Falco logs for error alert:
```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco | grep "Log File Deletion in Container"
```

3. Clean up:
```bash
kubectl delete pod test-log-del test-log-unlink --ignore-not-found
```

