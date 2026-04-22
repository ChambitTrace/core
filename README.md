# Chambit Core
Kubernetes in-node eBPF agent that forwards node/process events to Kafka.

## Build Image
```bash
git clone --recurse-submodules https://github.com/ChambitTrace/core
cd core
git submodule update --init --recursive
docker build -t ghcr.io/chambittrace/core:v1.0.4 .
```

## K3s Homelab Deployment (External Kafka VM)
This repository is tuned for a homelab topology where:
- K3s cluster traffic uses LAN (`192.168.200.0/24`)
- Ops/admin access uses Tailscale
- Kafka runs on a separate VM (outside the Kubernetes cluster)

### 1) Set Kafka VM endpoint
Edit [`Daemonset.yaml`](./Daemonset.yaml) ConfigMap values:
- `KAFKA_BROKERS`: Kafka VM address (LAN first, optional tailscale fallback)
- `KAFKA_TOPIC`: topic for eBPF events
- `CLUSTER_NAME`: logical cluster identifier

Example:
```yaml
KAFKA_BROKERS: "192.168.200.50:9092,100.88.10.20:9092"
KAFKA_TOPIC: "chambit-ebpf-events"
CLUSTER_NAME: "homelab-k3s"
```

### 2) Apply RBAC + DaemonSet
```bash
kubectl apply -f rbac.yaml
kubectl apply -f Daemonset.yaml
```

### 3) Check rollout
```bash
kubectl -n monitor get ds,pods -l app=chambit-innodeagent -o wide
kubectl -n monitor logs -l app=chambit-innodeagent --tail=100
```

## Kafka VM Listener Check (Important)
If pods cannot publish, verify Kafka broker listeners on the VM.

Example `server.properties`:
```properties
listeners=PLAINTEXT://0.0.0.0:9092
advertised.listeners=PLAINTEXT://192.168.200.50:9092
```

For dual path (LAN + Tailscale), add multiple listeners with named protocols and advertise both reachable endpoints.

## Runtime Environment Variables
- `KAFKA_BROKERS` (required): comma-separated broker list
- `KAFKA_TOPIC` (required): destination topic
- `KAFKA_BATCH_SIZE` (optional, default `100`)
- `KAFKA_BATCH_TIMEOUT_MS` (optional, default `1000`)
- `KAFKA_WRITE_TIMEOUT_MS` (optional, default `5000`)
- `CLUSTER_NAME` (optional, default `homelab-k3s`)
- `NODE_NAME` (set via downward API)
- `NODE_IP` (set via downward API)

## Message Flow
`eBPF Agent (DaemonSet) -> Kafka VM -> ELK`
