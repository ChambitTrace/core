# Makefile

BPF_CLANG = clang
BPF_CFLAGS = -g -O2 -target bpf \
             -D__TARGET_ARCH_x86 \
             -I. \
             -I/usr/include \
             -Wall -Wno-unused-variable

LIBBPF_DIR ?= ../../external/libbpf/src
LIBBPF_A = $(LIBBPF_DIR)/libbpf.a

LOADER_CC = gcc
LOADER_CFLAGS = -g -O2 -I$(LIBBPF_DIR)
# [수정됨] json-c 라이브러리를 링크하도록 -ljson-c 플래그를 추가합니다.
LOADER_LDFLAGS = $(LIBBPF_A) -lelf -lz -ljson-c

BPF_SRC = trace.bpf.c
BPF_OBJ = trace.bpf.o
BPF_SKEL = trace.skel.h
LOADER_SRC = loader.c
LOADER_BIN = loader

.PHONY: all clean

all: $(LOADER_BIN)

# BPF 컴파일 (CO-RE)
$(BPF_OBJ): $(BPF_SRC) event.h vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)

# Skeleton 생성
$(BPF_SKEL): $(BPF_OBJ)
	/usr/local/bin/bpftool gen skeleton $(BPF_OBJ) > $(BPF_SKEL)

# libbpf.a를 빌드하는 규칙
$(LIBBPF_A):
	$(MAKE) -C $(LIBBPF_DIR)

# 유저 로더 빌드 규칙
$(LOADER_BIN): $(LOADER_SRC) $(BPF_SKEL) event.h $(LIBBPF_A)
	$(LOADER_CC) $(LOADER_CFLAGS) -o $(LOADER_BIN) $(LOADER_SRC) $(LOADER_LDFLAGS)

clean:
	rm -f $(BPF_OBJ) $(BPF_SKEL) $(LOADER_BIN)
	$(MAKE) -C $(LIBBPF_DIR) clean