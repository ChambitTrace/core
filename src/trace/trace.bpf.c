#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "event.h"

// --- 맵 정의, 상수, 헬퍼 함수 (이전과 동일) ---
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct event_key);
    __type(value, __u64);
} last_event SEC(".maps");

const volatile __u64 DEBOUNCE_NS = 1000000000; // 1초

static __always_inline bool should_debounce(u32 pid, enum event_type type) {
    struct event_key key = {.pid = pid, .type = type};
    __u64 *last_ts = bpf_map_lookup_elem(&last_event, &key);
    if (!last_ts) return false;
    __u64 now = bpf_ktime_get_ns();
    if (now - *last_ts < DEBOUNCE_NS) return true;
    return false;
}

static __always_inline void record_event_timestamp(u32 pid, enum event_type type) {
    struct event_key key = {.pid = pid, .type = type};
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&last_event, &key, &now, BPF_ANY);
}

// ============================================================================
// ## 리팩토링 핵심: 핸들러 생성을 위한 매크로 정의 ##
// ============================================================================

// --- 패턴 1: 인자 없는 단순 이벤트 ---
#define TRACE_SIMPLE(name, type_enum)                                      \
SEC("tracepoint/syscalls/sys_enter_" #name)                                \
int tracepoint_##name(struct trace_event_raw_sys_enter *ctx) {             \
    u32 pid = bpf_get_current_pid_tgid() >> 32;                            \
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);       \
    if (!e) return 0;                                                      \
    e->pid = pid;                                                          \
    e->type = type_enum;                                                   \
    e->cgroup_id = bpf_get_current_cgroup_id();                            \
    bpf_get_current_comm(&e->comm, sizeof(e->comm));                       \
    bpf_ringbuf_submit(e, 0);                                              \
    return 0;                                                              \
}

// --- 패턴 2: 인자 없는 이벤트 + 중복 제거 ---
#define TRACE_SIMPLE_DEBOUNCED(name, type_enum)                            \
SEC("tracepoint/syscalls/sys_enter_" #name)                                \
int tracepoint_##name(struct trace_event_raw_sys_enter *ctx) {             \
    u32 pid = bpf_get_current_pid_tgid() >> 32;                            \
    if (should_debounce(pid, type_enum)) return 0;                         \
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);       \
    if (!e) return 0;                                                      \
    e->pid = pid;                                                          \
    e->type = type_enum;                                                   \
    e->cgroup_id = bpf_get_current_cgroup_id();                            \
    bpf_get_current_comm(&e->comm, sizeof(e->comm));                       \
    bpf_ringbuf_submit(e, 0);                                              \
    record_event_timestamp(pid, type_enum);                                \
    return 0;                                                              \
}

// --- 패턴 3: 파일 경로 인자 이벤트 + 중복 제거 ---
#define TRACE_FILENAME_DEBOUNCED(name, type_enum, arg_idx)                  \
SEC("tracepoint/syscalls/sys_enter_" #name)                                 \
int tracepoint_##name(struct trace_event_raw_sys_enter *ctx) {              \
    u32 pid = bpf_get_current_pid_tgid() >> 32;                             \
    if (should_debounce(pid, type_enum)) return 0;                          \
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);        \
    if (!e) return 0;                                                       \
    bpf_probe_read_user_str(&e->args.filename, sizeof(e->args.filename),    \
                            (void *)ctx->args[arg_idx]);                     \
    e->pid = pid;                                                           \
    e->type = type_enum;                                                    \
    e->cgroup_id = bpf_get_current_cgroup_id();                             \
    bpf_get_current_comm(&e->comm, sizeof(e->comm));                        \
    bpf_ringbuf_submit(e, 0);                                               \
    record_event_timestamp(pid, type_enum);                                 \
    return 0;                                                               \
}


// ============================================================================
// ## 시스템 콜 핸들러: 매크로를 사용하여 간결하게 정의 ##
// ============================================================================

// --- 프로세스 관련 ---
// execve, ptrace 등은 특수 처리 필요 또는 단순하여 매크로 미사용
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->type = EVENT_TYPE_EXEC;
    e->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->args.filename, sizeof(e->args.filename), (void *)ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
SEC("tracepoint/syscalls/sys_enter_execveat")
int tracepoint_execveat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->type = EVENT_TYPE_EXEC;
    e->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->args.filename, sizeof(e->args.filename), (void *)ctx->args[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
SEC("tracepoint/sched/sched_process_fork") // fork/clone은 특수 핸들러 사용
int tracepoint_sched_fork(struct trace_event_raw_sched_process_fork *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = ctx->parent_pid;
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->type = EVENT_TYPE_FORK_CLONE;
    bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm), ctx->parent_comm);
    e->args.fork_info.parent_pid = ctx->parent_pid;
    e->args.fork_info.child_pid = ctx->child_pid;
    bpf_ringbuf_submit(e, 0);
    return 0;
}
TRACE_SIMPLE(ptrace, EVENT_TYPE_PTRACE)

// --- 파일 시스템 관련 ---
TRACE_FILENAME_DEBOUNCED(open,  EVENT_TYPE_OPEN, 0)
TRACE_FILENAME_DEBOUNCED(creat, EVENT_TYPE_OPEN, 0)
// openat은 arg1을 사용하므로 특수 핸들러 유지
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_openat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (should_debounce(pid, EVENT_TYPE_OPEN)) return 0;
    const char *pathname_ptr;
    bpf_probe_read_kernel(&pathname_ptr, sizeof(pathname_ptr), &ctx->args[1]);
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->type = EVENT_TYPE_OPEN;
    e->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->args.filename, sizeof(e->args.filename), pathname_ptr);
    bpf_ringbuf_submit(e, 0);
    record_event_timestamp(pid, EVENT_TYPE_OPEN);
    return 0;
}

TRACE_SIMPLE_DEBOUNCED(read,  EVENT_TYPE_READ)
TRACE_SIMPLE_DEBOUNCED(write, EVENT_TYPE_WRITE)

SEC("tracepoint/syscalls/sys_enter_chmod") // chmod/chown 등은 특수 인자 처리
int tracepoint_chmod(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->type = EVENT_TYPE_CHMOD;
    e->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->args.filename, sizeof(e->args.filename), (void *)ctx->args[0]);
    e->args.perm_info.mode = (unsigned int)ctx->args[1];
    bpf_ringbuf_submit(e, 0);
    return 0;
}
TRACE_SIMPLE(fchmod, EVENT_TYPE_CHMOD) // fchmod는 파일명 없음
SEC("tracepoint/syscalls/sys_enter_chown")
int tracepoint_chown(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->type = EVENT_TYPE_CHOWN;
    e->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->args.filename, sizeof(e->args.filename), (void *)ctx->args[0]);
    e->args.perm_info.uid = (unsigned int)ctx->args[1];
    e->args.perm_info.gid = (unsigned int)ctx->args[2];
    bpf_ringbuf_submit(e, 0);
    return 0;
}
TRACE_SIMPLE(mount, EVENT_TYPE_MOUNT) // mount는 단순 추적으로 변경

// --- 권한 관련 ---
SEC("tracepoint/syscalls/sys_enter_setuid")
int tracepoint_setuid(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->type = EVENT_TYPE_SETUID;
    e->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->args.perm_info.uid = (unsigned int)ctx->args[0];
    bpf_ringbuf_submit(e, 0);
    return 0;
}
SEC("tracepoint/syscalls/sys_enter_setgid")
int tracepoint_setgid(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->type = EVENT_TYPE_SETGID;
    e->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->args.perm_info.gid = (unsigned int)ctx->args[0];
    bpf_ringbuf_submit(e, 0);
    return 0;
}
TRACE_SIMPLE(capset,  EVENT_TYPE_CAPSET)
TRACE_SIMPLE(unshare, EVENT_TYPE_UNSHARE)
TRACE_SIMPLE(setns,   EVENT_TYPE_SETNS)

// --- 커널 모듈 및 BPF 관련 ---
TRACE_SIMPLE(init_module,   EVENT_TYPE_MODULE)
TRACE_SIMPLE(finit_module,  EVENT_TYPE_MODULE)
TRACE_SIMPLE(delete_module, EVENT_TYPE_MODULE)
TRACE_SIMPLE(bpf,           EVENT_TYPE_BPF)


char LICENSE[] SEC("license") = "GPL";
