FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# 1. 필수 패키지 설치
RUN apt-get update && \
    apt-get install -y \
    clang llvm gcc make git curl \
    libelf-dev zlib1g-dev libbpf-dev \
    iproute2 \
    libjson-c-dev

# bpftool with libbpf (submodule)
RUN git clone --recurse-submodules https://github.com/libbpf/bpftool.git /tmp/bpftool && \
    cd /tmp/bpftool/src && make && \
    cp bpftool /usr/local/bin/ && \
    rm -rf /tmp/bpftool


# 2. 작업 디렉토리 설정
WORKDIR /app

# 3. 전체 프로젝트 복사
COPY . .

# 4. 빌드 (trace 디렉토리로 이동 후 make)
WORKDIR /app/src/trace
RUN make

# 5. entrypoint 지정
ENTRYPOINT ["./loader"]
