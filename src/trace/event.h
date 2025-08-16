#ifndef __EVENT_H__
#define __EVENT_H__

#define TASK_COMM_LEN 16
#define MAX_STRING_LEN 256

// (이전과 동일)
enum event_type {
	EVENT_TYPE_EXEC,
	EVENT_TYPE_FORK_CLONE,
	EVENT_TYPE_PTRACE,
	EVENT_TYPE_OPEN,
	EVENT_TYPE_READ,
	EVENT_TYPE_WRITE,
	EVENT_TYPE_CHMOD,
	EVENT_TYPE_CHOWN,
	EVENT_TYPE_MOUNT,
	EVENT_TYPE_SETUID,
	EVENT_TYPE_SETGID,
	EVENT_TYPE_CAPSET,
	EVENT_TYPE_UNSHARE,
	EVENT_TYPE_SETNS,
	EVENT_TYPE_MODULE,
	EVENT_TYPE_BPF,
};

// [추가] BPF 맵에서 중복 이벤트를 추적하기 위한 키
struct event_key {
	__u32 pid;
	enum event_type type;
};

// (event_t 구조체는 이전과 동일)
struct event_t {
	__u64 cgroup_id;
	__u32 pid;
	char comm[TASK_COMM_LEN];
	enum event_type type;
	union {
		char filename[MAX_STRING_LEN];
		struct {
			__u32 parent_pid;
			__u32 child_pid;
		} fork_info;
		struct {
			__u32 uid;
			__u32 gid;
			__u32 mode;
		} perm_info;
	} args;
};

#endif /* __EVENT_H__ */