BPF_CLANG = clang
BPF_CFLAGS = -g -O2 -target bpf                     \
             -D__TARGET_ARCH_x86                   \
             -I. -I/usr/include                    \
             -Wall -Wno-unused-variable
LIBBPF_DIR ?= ../../external/libbpf/src
LOADER_CC = gcc
LOADER_CFLAGS = -g -O2 -I$(LIBBPF_DIR)
LOADER_LDFLAGS = $(LIBBPF_DIR)/libbpf.a -lelf -lz

BPF_SRC = trace.bpf.c
BPF_OBJ = trace.bpf.o
BPF_SKEL = trace.skel.h
LOADER_SRC = loader.c
LOADER_BIN = loader

.PHONY: all clean

all: $(LOADER_BIN)

# 1. BPF 컴파일 (CO-RE)
$(BPF_OBJ): $(BPF_SRC) event.h vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)

# 2. Skeleton 생성
$(BPF_SKEL): $(BPF_OBJ)
	/usr/local/bin/bpftool gen skeleton $(BPF_OBJ) > $(BPF_SKEL)

# 3. 유저 로더 빌드
$(LOADER_BIN): $(LOADER_SRC) $(BPF_SKEL) event.h
	$(LOADER_CC) $(LOADER_CFLAGS) -o $(LOADER_BIN) $(LOADER_SRC) $(LOADER_LDFLAGS)

clean:
	rm -f $(BPF_OBJ) $(BPF_SKEL) $(LOADER_BIN)
