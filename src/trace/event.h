#ifndef __EVENT_H__
#define __EVENT_H__

// CO-RE friendly: 사용자 정의 타입만 사용
typedef unsigned int __u32;

struct event_t {
    __u32 pid;
    char filename[256];
};

#endif
