#ifndef __EVENT_H__
#define __EVENT_H__

typedef unsigned int __u32;
typedef unsigned long long __u64;

struct event_t {
    __u32 pid;
    char filename[256];
    char comm[16]; // 프로세스 이름
    __u64 cgroup_id;
};

#endif