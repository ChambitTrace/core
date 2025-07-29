#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 128

// [수정] 모든 시스템 콜을 포함하도록 이벤트 타입 확장
enum event_type {
	// 프로세스
	EVENT_TYPE_EXECVE,
	EVENT_TYPE_EXECVEAT,
	EVENT_TYPE_FORK_CLONE, // fork와 clone을 함께 처리
	EVENT_TYPE_PTRACE,
	// 파일 시스템
	EVENT_TYPE_OPEN,
	EVENT_TYPE_OPENAT,
	EVENT_TYPE_CREAT,
	EVENT_TYPE_READ,
	EVENT_TYPE_WRITE,
	EVENT_TYPE_CHMOD,
	EVENT_TYPE_FCHMOD,
	EVENT_TYPE_CHOWN,
	EVENT_TYPE_MOUNT,
	// 권한
	EVENT_TYPE_SETUID,
	EVENT_TYPE_SETGID,
	EVENT_TYPE_CAPSET,
	EVENT_TYPE_UNSHARE,
	EVENT_TYPE_SETNS,
	// 커널 모듈 및 BPF
	EVENT_TYPE_INIT_MODULE,
	EVENT_TYPE_FINIT_MODULE,
	EVENT_TYPE_DELETE_MODULE,
	EVENT_TYPE_BPF,
};

// [수정] 다양한 인자를 처리하기 위한 구조체
struct event {
	__u64 cgroup_id;
	__u32 pid;
	char comm[TASK_COMM_LEN];
	enum event_type type;

	union {
		// 파일 경로를 인자로 갖는 시스템 콜
		char filename[MAX_FILENAME_LEN];
		// 권한 관련 시스템 콜
		uid_t uid;
		gid_t gid;
		mode_t mode;
		// fork/clone
		__u32 child_pid;
	} args;
};

// Ring Buffer 맵 (변경 없음)
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");


// --- 매크로 정의 (코드 중복 최소화) ---

// [추가] 인자 없이 호출 자체만 감시하는 시스템 콜을 위한 매크로
#define TRACE_SYSCALL_SIMPLE(name, type_enum)                                  \
    SEC("tracepoint/syscalls/sys_enter_" #name)                                \
    int tracepoint__syscalls__sys_enter_##name(                                \
        struct trace_event_raw_sys_enter *ctx) {                               \
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);         \
        if (!e) return 0;                                                      \
        e->cgroup_id = bpf_get_current_cgroup_id();                            \
        e->pid = bpf_get_current_pid_tgid() >> 32;                             \
        e->type = type_enum;                                                   \
        bpf_get_current_comm(&e->comm, sizeof(e->comm));                       \
        bpf_ringbuf_submit(e, 0);                                              \
        return 0;                                                              \
    }

#define TRACE_SYSCALL_FILENAME(name, type_enum)                                \
    SEC("tracepoint/syscalls/sys_enter_" #name)                                \
    int tracepoint__syscalls__sys_enter_##name(                                \
        struct trace_event_raw_sys_enter *ctx) {                               \
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);         \
        if (!e) return 0;                                                      \
        e->cgroup_id = bpf_get_current_cgroup_id();                            \
        e->pid = bpf_get_current_pid_tgid() >> 32;                             \
        e->type = type_enum;                                                   \
        bpf_get_current_comm(&e->comm, sizeof(e->comm));                       \
        /* [수정] e->filename -> e->args.filename 으로 변경 */                 \
        bpf_probe_read_user_str(&e->args.filename, sizeof(e->args.filename),   \
                                (char *)ctx->args[0]);                         \
        bpf_ringbuf_submit(e, 0);                                              \
        return 0;                                                              \
    }

// --- 시스템 콜 핸들러 ---

// 프로세스 관련
TRACE_SYSCALL_FILENAME(execve, EVENT_TYPE_EXECVE)
TRACE_SYSCALL_FILENAME(execveat, EVENT_TYPE_EXECVEAT)
TRACE_SYSCALL_SIMPLE(ptrace, EVENT_TYPE_PTRACE)

// 파일 시스템 관련
TRACE_SYSCALL_FILENAME(open, EVENT_TYPE_OPEN)
TRACE_SYSCALL_FILENAME(creat, EVENT_TYPE_CREAT)
TRACE_SYSCALL_FILENAME(chmod, EVENT_TYPE_CHMOD) 
TRACE_SYSCALL_FILENAME(chown, EVENT_TYPE_CHOWN) // uid, gid는 잡으려면 별도 핸들러 필요 코드 정상작동 보고 차후 개발
TRACE_SYSCALL_FILENAME(mount, EVENT_TYPE_MOUNT)
TRACE_SYSCALL_SIMPLE(read, EVENT_TYPE_READ)
TRACE_SYSCALL_SIMPLE(write, EVENT_TYPE_WRITE)
TRACE_SYSCALL_SIMPLE(fchmod, EVENT_TYPE_FCHMOD)

// openat은 두 번째 인자가 파일 경로임
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(
	struct trace_event_raw_sys_enter *ctx) {
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) return 0;
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->type = EVENT_TYPE_OPENAT;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_user_str(&e->args.filename, sizeof(e->args.filename),
							(char *)ctx->args[1]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// fork와 clone은 sched_process_fork로 한번에 처리
SEC("tracepoint/sched/sched_process_fork")
int tracepoint__sched__sched_process_fork(
	struct trace_event_raw_sched_process_fork *ctx) {
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) return 0;
	e->cgroup_id = bpf_get_current_cgroup_id();
	// 부모 PID
	e->pid = ctx->parent_pid;
	e->type = EVENT_TYPE_FORK_CLONE;
	bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm), ctx->parent_comm);
	// 자식 PID
	e->args.child_pid = ctx->child_pid;
	bpf_ringbuf_submit(e, 0);
	return 0;
}


// 권한 관련
TRACE_SYSCALL_SIMPLE(setuid, EVENT_TYPE_SETUID)
TRACE_SYSCALL_SIMPLE(setgid, EVENT_TYPE_SETGID)
TRACE_SYSCALL_SIMPLE(capset, EVENT_TYPE_CAPSET)
TRACE_SYSCALL_SIMPLE(unshare, EVENT_TYPE_UNSHARE)
TRACE_SYSCALL_SIMPLE(setns, EVENT_TYPE_SETNS)

// 커널 모듈 및 BPF
TRACE_SYSCALL_SIMPLE(init_module, EVENT_TYPE_INIT_MODULE)
TRACE_SYSCALL_SIMPLE(finit_module, EVENT_TYPE_FINIT_MODULE)
TRACE_SYSCALL_SIMPLE(delete_module, EVENT_TYPE_DELETE_MODULE)
TRACE_SYSCALL_SIMPLE(bpf, EVENT_TYPE_BPF)

char LICENSE[] SEC("license") = "GPL";
