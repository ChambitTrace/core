# Chambit_Core
Kubernetes in node Agent

## Usage in Docker
```
git clone --recurse-submodules https://github.com/ChambitTrace/core

cd core 

git submodule update --init --recursive 

docker build -t <image-name> .

docker run -d \
  --name chambitAgent \
  --privileged \
  --cap-add=SYS_ADMIN --cap-add=SYS_RESOURCE \
  --mount type=bind,src=/sys,target=/sys \
  --mount type=bind,src=/sys/fs/bpf,target=/sys/fs/bpf \
  --mount type=bind,src=/var/log,target=/host/var/log \
  <image-name>
```
or
```
docker pull ghcr.io/chambittrace/core:v1.0.1
docker run -d \
  --name chambitAgent \
  --privileged \
  --cap-add=SYS_ADMIN --cap-add=SYS_RESOURCE \
  --mount type=bind,src=/sys,target=/sys \
  --mount type=bind,src=/sys/fs/bpf,target=/sys/fs/bpf \
  --mount type=bind,src=/var/log,target=/host/var/log \
  ghcr.io/chambittrace/core:v1.0.1
```
- You can check the log through ebpf with the code below.
```
docker exec -it <continer-name> bash
sudo tail -f /host/var/log/ebpf_exec.log
```