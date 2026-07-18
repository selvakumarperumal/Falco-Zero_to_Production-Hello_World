# Crypto Mining Process Detected

| Property | Value |
|---|---|
| **Type** | Falco (Detection Only) |
| **Kyverno Prevention** | N/A (Runtime behavior, cannot be prevented at admission time). |
| **Falco Detection** | eBPF syscall analysis matching executed process names or arguments against known miner lists. |

## Description
Detects execution of known cryptocurrency mining processes (e.g., `xmrig`, `minerd`) or command line arguments indicating connection to mining pools (e.g., `stratum+tcp://`).

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
