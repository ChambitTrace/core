# Chambit Core
Kubernetes in-node eBPF agent that forwards node/process events to Kafka.

This agent does not scrape Pod stdout/stderr logs like Fluent Bit, Vector, or Promtail.
It captures kernel and process-level events from Linux nodes via eBPF and enriches them with Kubernetes Pod context before publishing to Kafka.

## Build Image
```bash
git clone --recurse-submodules https://github.com/ChambitTrace/core
cd core
git submodule update --init --recursive
docker build -t ghcr.io/chambittrace/core:v1.0.4 .
```

## Proxmox Kubernetes Deployment (Kafka on Mac mini)
This repository can be deployed in a homelab topology where:
- the Kubernetes cluster runs on an HP Z440 with Proxmox
- the operator workstation is a Mac mini on the same LAN
- Kafka runs in Docker on the Mac mini
- Tailscale exists for management traffic, but Kafka can use the simpler LAN path
- Kubernetes worker nodes are `linux/amd64`

### 1) Set Kafka VM endpoint
Edit [`Daemonset.yaml`](./Daemonset.yaml) ConfigMap values:
- `KAFKA_BROKERS`: Mac mini Kafka address (LAN first, optional tailscale fallback)
- `KAFKA_TOPIC`: topic for eBPF events
- `CLUSTER_NAME`: logical cluster identifier

Example:
```yaml
KAFKA_BROKERS: "192.168.200.178:9092"
KAFKA_TOPIC: "chambit-ebpf-events"
CLUSTER_NAME: "proxmox-k8s"
```

If you want a single file deploy, edit the same values in [`runtimeAgent.yaml`](./runtimeAgent.yaml) and apply that file directly.

### 2) Run Kafka on the Mac mini
Create a local env file from the example and keep the advertised host set to the Mac mini LAN IP:
```bash
cp .env.kafka.example .env.kafka
docker compose -f docker-compose.kafka.yml up -d
```

### 3) Apply RBAC + DaemonSet
```bash
kubectl apply -f rbac.yaml
kubectl apply -f Daemonset.yaml
```

Or with the all-in-one manifest:
```bash
kubectl apply -f runtimeAgent.yaml
```

### 4) Check rollout
```bash
kubectl -n monitor get ds,pods -l app=chambit-innodeagent -o wide
kubectl -n monitor logs -l app=chambit-innodeagent --tail=100
```

### 5) Check Kafka receives data
```bash
docker exec -it chambit-kafka kafka-topics --bootstrap-server 127.0.0.1:9092 --list
docker exec -it chambit-kafka kafka-console-consumer --bootstrap-server 127.0.0.1:9092 --topic chambit-ebpf-events --from-beginning
```

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
`eBPF Agent (DaemonSet) -> Kafka on Mac mini Docker -> ELK`

## Important Scope
What this agent sends to Kafka:
- exec, open, mount, chmod, chown, setuid/setgid, ptrace, bpf, module and related runtime events
- node identity (`NODE_NAME`, `NODE_IP`, `CLUSTER_NAME`)
- resolved Kubernetes pod context from cgroup metadata

What this agent does not send by itself:
- application stdout/stderr log lines from containers
- Kubernetes Event objects from the API server

If you need container log shipping, pair this with a log collector such as Fluent Bit or Vector and keep Chambit for runtime tracing.
