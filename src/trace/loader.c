#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include "trace.skel.h"  // BPF skeleton from bpftool
#include "event.h"
#include <json-c/json.h>
#include <time.h>
#include <sys/resource.h>

void bump_memlock_rlimit(void) {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &r);
}

static volatile bool exiting = false;

void handle_signal(int sig) {
    exiting = true;
}

// 이벤트 핸들러
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event_t *e = data;
    // printf("[exec] PID: %d | Path: %s\n", e->pid, e->filename);
    // 시간 스탬프 생성
    time_t now = time(NULL);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%FT%T%z", localtime(&now));

    // 로그 파일 경로 (DaemonSet에서 hostPath로 마운트된 디렉토리)
    FILE *f = fopen("/host/var/log/ebpf_exec.log", "a");
    if (!f) return 0;

    // JSON 형식으로 로그 작성
    fprintf(f,
        "{ \"timestamp\": \"%s\", \"pid\": %d, \"path\": \"%s\" }\n",
        timebuf, e->pid, e->filename);

    fclose(f);
    return 0;
}

int main() {
    bump_memlock_rlimit();
    
    struct trace_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;
    
    signal(SIGINT, handle_signal);

    // Skeleton 로드
    skel = trace_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF program\n");
        return 1;
    }

    // Attach probe
    err = trace_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program\n");
        return 1;
    }

    // 링 버퍼 연결
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    printf("Listening for events...\n");

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
