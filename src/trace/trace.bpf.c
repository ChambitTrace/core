// trace_sbom.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "event.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1<<24);
} events SEC(".maps");


// execve
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *event;
    const char *filename = (const char *)ctx->args[0];
    
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        bpf_printk("Failed to reserve space in ring buffer\n");
        return 0;
    }

    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// open
// SEC("tracepoint/syscalls/sys_enter_open")
// int trace_open(struct trace_event_raw_sys_enter *ctx) {
//     char filename[256];
//     bpf_probe_read_user_str(filename, sizeof(filename), (void *)ctx->args[0]);
//     bpf_printk("SBOM open: %s\n", filename);
//     return 0;
// }

// // openat
// SEC("tracepoint/syscalls/sys_enter_openat")
// int trace_openat(struct trace_event_raw_sys_enter *ctx) {
//     char filename[256];
//     bpf_probe_read_user_str(filename, sizeof(filename), (void *)ctx->args[1]);
//     bpf_printk("SBOM openat: %s\n", filename);
//     return 0;
// }

// // creat
// SEC("tracepoint/syscalls/sys_enter_creat")
// int trace_creat(struct trace_event_raw_sys_enter *ctx) {
//     char filename[256];
//     bpf_probe_read_user_str(filename, sizeof(filename), (void *)ctx->args[0]);
//     bpf_printk("SBOM creat: %s\n", filename);
//     return 0;
// }


// // mmap (mmap2는 아키텍처별로 다름, x86_64는 mmap)
// // x86_64, arm64 등에서 자동 attach
// SEC("tracepoint/syscalls/sys_enter_mmap")
// int trace_mmap(struct trace_event_raw_sys_enter *ctx) {
//     bpf_printk("SBOM mmap called!\n");
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_enter_mmap2")
// int trace_mmap2(struct trace_event_raw_sys_enter *ctx) {
//     bpf_printk("SBOM mmap2 called!\n");
//     return 0;
// }

// // readlink
// SEC("tracepoint/syscalls/sys_enter_readlink")
// int trace_readlink(struct trace_event_raw_sys_enter *ctx) {
//     char pathname[256];
//     bpf_probe_read_user_str(pathname, sizeof(pathname), (void *)ctx->args[0]);
//     bpf_printk("SBOM readlink: %s\n", pathname);
//     return 0;
// }
