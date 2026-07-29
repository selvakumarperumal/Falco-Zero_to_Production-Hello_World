# Crypto Mining Process Detected

| Property | Value |
|---|---|
| **Type** | Falco (Detection Only) |
| **Kyverno Prevention** | N/A (Runtime behavior, cannot be prevented at admission time). |
| **Falco Detection** | eBPF syscall analysis matching executed process names or arguments against known miner lists. |

## Description
Detects execution of known cryptocurrency mining processes (e.g., `xmrig`, `minerd`) or command line arguments indicating connection to mining pools (e.g., `stratum+tcp://`).

### 🛡️ Problem Statement — What Are We Preventing?

Cryptojacking — the unauthorized use of compute resources to mine cryptocurrency — is one of the most common attacks targeting Kubernetes clusters. Attackers exploit vulnerable applications, misconfigured RBAC, or compromised container images to deploy crypto miners inside containers. This policy detects and alerts on such activity because:

* **Financial Impact**: Crypto miners consume 100% of available CPU and GPU resources, directly inflating cloud compute bills. Organizations have reported surprise bills of tens of thousands of dollars from undetected mining operations running over weekends or holidays.
* **Resource Hijacking (MITRE ATT&CK: T1496)**: Mining processes starve legitimate application workloads of CPU and memory, causing degraded performance, increased latency, and SLA violations for customer-facing services. In severe cases, mining activity can trigger node-level OOM kills that cascade across pods.
* **Indicator of Deeper Compromise**: The presence of a crypto miner almost always indicates a prior compromise — the attacker had to gain initial access (e.g., RCE vulnerability, leaked credentials, supply chain attack) before deploying the miner. Mining activity is therefore a strong signal that the cluster's security perimeter has been breached and further investigation is needed.
* **Lateral Movement Risk**: Attackers who deploy miners often also deploy persistence mechanisms (e.g., cron jobs, modified container images) and attempt lateral movement to other namespaces or nodes to maximize mining output.
* **Regulatory and Compliance Violations**: Running unauthorized workloads on infrastructure subject to compliance frameworks (HIPAA, PCI-DSS, SOC2) can constitute a reportable security incident.

**Falco detects this** by monitoring process execution syscalls (`execve`) inside containers and matching process names against a curated list of known mining binaries (e.g., `xmrig`, `minerd`, `ethminer`) and mining pool connection patterns (`stratum+tcp://`, `cryptonight`, `randomx`), firing a `CRITICAL` alert for immediate incident response.


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
    - list: crypto_mining_processes
      items:
        - xmrig
        - minerd
        - minergate
        - cpuminer
        - ethminer
        - cgminer
        - bfgminer
        - nbminer
        - t-rex
        - gminer
        - lolminer

    - rule: Crypto Mining Process Detected
      desc: >
        Detects known cryptocurrency mining processes or connections to
        known mining pool domains.
      source: syscall
      condition: >
        evt.type in (execve, execveat) and evt.failed = false and container
        and (proc.name in (crypto_mining_processes)
          or proc.cmdline contains "stratum+tcp://"
          or proc.cmdline contains "stratum+ssl://"
          or proc.cmdline icontains "cryptonight"
          or proc.cmdline icontains "randomx")
      output: >
        Crypto mining detected (command=%proc.cmdline pod=%k8s.pod.name
        ns=%k8s.ns.name image=%container.image.repository user=%user.name)
      priority: CRITICAL
      tags: [runtime_only, crypto_mining, mitre_resource_hijacking]
```

## Detailed Explanation
### Falco Rule Manifest Explanation
The rule captures runtime cryptocurrency hijacking behavior:
- **`list: crypto_mining_processes`**: Defines a list of known crypto mining executable names (like `xmrig`, `minerd`).
- **`condition`**: Triggers when all the following evaluate to true:
  - `spawned_process`: A new program/process execution event (syscall `execve`).
  - `container`: The event originates inside a container (not the host).
  - The process name (`proc.name`) is in the `crypto_mining_processes` list OR the command line (`proc.cmdline`) contains stratum protocols (`stratum+tcp://`, `stratum+ssl://`) or miner algorithms (`cryptonight`, `randomx`).
- **`output`**: Details the command, pod, namespace, image, and executing user.
- **`priority: CRITICAL`**: Marks it as a critical severity incident, as cryptojacking consumes extensive CPU resources and billings.

## Test Scenarios & Manifest Examples

### 1. 🚨 RUNTIME ALERT CASE 1 — Known Mining Binary Name (`xmrig`)
```bash
# Executing a process named xmrig inside a container
kubectl run test-miner-binary --image=alpine --restart=Never -- sh -c "exec -a xmrig sleep 60"
```
* **Result**: **ALERT (CRITICAL)** — `proc.name` matches item in `crypto_mining_processes` list. Falco emits `Crypto Mining Process Detected`.

---

### 2. 🚨 RUNTIME ALERT CASE 2 — Stratum Protocol in Command Line
```bash
# Command line arguments specifying a stratum pool URL
kubectl run test-stratum-cmd --image=alpine --restart=Never -- sh -c "sleep 60 --url=stratum+tcp://pool.supportxmr.com:5555"
```
* **Result**: **ALERT (CRITICAL)** — `proc.cmdline` contains `"stratum+tcp://"`. Falco triggers a critical alert.

---

### 3. ✅ NORMAL OPERATION — Standard Application Workload
```bash
# Running legitimate application process
kubectl run test-normal-app --image=nginx:1.25 --restart=Never
```
* **Result**: **NO ALERT** — Process name (`nginx`) and command line parameters do not match any miner pattern.

---

## How to Test

### Falco (Runtime Execution Test)
1. Spin up a temporary pod and simulate a mining execution using `exec -a`:
```bash
kubectl run test-miner --image=alpine --restart=Never -it -- sh -c "sleep 1 && exec -a xmrig sleep 10"
```

2. Check Falco logs or Falcosidekick UI for critical alert:
```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco | grep "Crypto Mining Process Detected"
```

3. Clean up:
```bash
kubectl delete pod test-miner test-miner-binary test-stratum-cmd test-normal-app --ignore-not-found
```

