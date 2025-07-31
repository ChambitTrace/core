#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>
#include <json-c/json.h>
#include <linux/types.h>

#include "trace.skel.h"
#include "event.h"

// 이벤트 타입 enum을 문자열로 변환하는 함수
const char* event_type_to_string(enum event_type type) {
    switch(type) {
        case EVENT_TYPE_EXEC: return "EXEC";
        case EVENT_TYPE_FORK_CLONE: return "FORK_CLONE";
        case EVENT_TYPE_PTRACE: return "PTRACE";
        case EVENT_TYPE_OPEN: return "OPEN";
        case EVENT_TYPE_READ: return "READ";
        case EVENT_TYPE_WRITE: return "WRITE";
        case EVENT_TYPE_CHMOD: return "CHMOD";
        case EVENT_TYPE_CHOWN: return "CHOWN";
        case EVENT_TYPE_MOUNT: return "MOUNT";
        case EVENT_TYPE_SETUID: return "SETUID";
        case EVENT_TYPE_SETGID: return "SETGID";
        case EVENT_TYPE_CAPSET: return "CAPSET";
        case EVENT_TYPE_UNSHARE: return "UNSHARE";
        case EVENT_TYPE_SETNS: return "SETNS";
        case EVENT_TYPE_MODULE: return "MODULE";
        case EVENT_TYPE_BPF: return "BPF";
        default: return "UNKNOWN";
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event_t *e = data;
    json_object *jobj = json_object_new_object();

    // 공통 정보 추가
    json_object_object_add(jobj, "type", json_object_new_string(event_type_to_string(e->type)));
    json_object_object_add(jobj, "pid", json_object_new_int(e->pid));
    json_object_object_add(jobj, "comm", json_object_new_string(e->comm));
    json_object_object_add(jobj, "cgroup_id", json_object_new_int64(e->cgroup_id));

    // 이벤트 타입에 따른 상세 정보 추가
    switch(e->type) {
        case EVENT_TYPE_EXEC:
        case EVENT_TYPE_OPEN:
        case EVENT_TYPE_MOUNT:
            json_object_object_add(jobj, "filename", json_object_new_string(e->args.filename));
            break;
        case EVENT_TYPE_FORK_CLONE:
            json_object_object_add(jobj, "parent_pid", json_object_new_int(e->args.fork_info.parent_pid));
            json_object_object_add(jobj, "child_pid", json_object_new_int(e->args.fork_info.child_pid));
            break;
        case EVENT_TYPE_CHMOD:
            json_object_object_add(jobj, "filename", json_object_new_string(e->args.filename));
            json_object_object_add(jobj, "mode", json_object_new_int(e->args.perm_info.mode));
            break;
        case EVENT_TYPE_CHOWN:
            json_object_object_add(jobj, "filename", json_object_new_string(e->args.filename));
            json_object_object_add(jobj, "uid", json_object_new_int(e->args.perm_info.uid));
            json_object_object_add(jobj, "gid", json_object_new_int(e->args.perm_info.gid));
            break;
        case EVENT_TYPE_SETUID:
            json_object_object_add(jobj, "uid", json_object_new_int(e->args.perm_info.uid));
            break;
        case EVENT_TYPE_SETGID:
            json_object_object_add(jobj, "gid", json_object_new_int(e->args.perm_info.gid));
            break;
        default:
            // 추가 정보 없음
            break;
    }

    printf("%s\n", json_object_to_json_string(jobj));
    fflush(stdout);
    json_object_put(jobj); // 메모리 해제
    return 0;
}


// main 함수와 나머지 코드는 수정 없이 그대로 사용
void bump_memlock_rlimit(void) {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &r);
}

static volatile bool exiting = false;

void handle_signal(int sig) {
    exiting = true;
}

int main() {
    bump_memlock_rlimit();
    struct trace_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;
    signal(SIGINT, handle_signal);

    skel = trace_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF program\n");
        return 1;
    }

    err = trace_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program\n");
        return 1;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* ms */);
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer\n");
            break;
        }
    }

    ring_buffer__free(rb);
    trace_bpf__destroy(skel);
    return 0;
}
