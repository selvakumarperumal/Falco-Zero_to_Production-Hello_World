# Crypto Mining Process Detected

| Property | Value |
|---|---|
| **Type** | Falco (Detection Only) |
| **Kyverno Prevention** | N/A (Runtime behavior, cannot be prevented at admission time). |
| **Falco Detection** | eBPF syscall analysis matching executed process names or arguments against known miner lists. |

## Description
Detects execution of known cryptocurrency mining processes (e.g., `xmrig`, `minerd`) or command line arguments indicating connection to mining pools (e.g., `stratum+tcp://`).

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

      source: syscall
        Detects known cryptocurrency mining processes or connections to
        known mining pool domains.
      condition: >
        spawned_process and container
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

## How to Test
1. Spin up a temporary pod and execute a command disguised under a miner process name:
```bash
kubectl run test-miner --image=alpine --restart=Never -it -- sh -c "sleep 1 && exec -a xmrig sleep 100"
```
2. Check your Falco log alerts or port-forward to the Falcosidekick UI to verify a `Crypto Mining Process Detected` critical alert has been fired.
3. Clean up the pod:
```bash
kubectl delete pod test-miner
```
