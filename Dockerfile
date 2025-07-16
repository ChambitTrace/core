FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# 1. 필수 패키지 설치
RUN apt-get update && \
    apt-get install -y \
    lsb-release gnupg software-properties-common wget

RUN wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 16

# 3. Clang 16 및 관련 도구 설치
RUN apt-get install -y \
    clang-16 llvm-16 lld-16 \
    gcc make git libelf-dev zlib1g-dev libbpf-dev \
    iproute2 libjson-c-dev
# libbpf 설치 git 사용



RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-16 100 && \
    update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-16 100

# 2. 작업 디렉토리 설정
WORKDIR /app

# 3. 전체 프로젝트 복사
COPY . .

# bpftool (submodule)
RUN cd /app/external/bpftool/src && make && cp bpftool /usr/local/bin/

# libbpf (submodule)
RUN cd external/libbpf/src && make && make install && make BUILD_STATIC_ONLY=y

# 4. 빌드 (trace 디렉토리로 이동 후 make)
RUN cd /app/src/trace && \
    make clean && \
    make

ENTRYPOINT ["./src/triger/main"]


# test
# ENTRYPOINT ["/bin/bash"]