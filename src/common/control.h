#pragma once

#ifdef USERSPACE_CODE
#include <sys/types.h>
#else
#include "common/vmlinux.h"
#endif

#define MAX_LIST_ITEMS 10

typedef enum
{
    NOT_SET = 0,
    IGNORE,
    CAPTURE
} trace_mode_t;

struct control_input
{
    trace_mode_t global_mode;

    trace_mode_t uid_mode;
    uid_t uids[MAX_LIST_ITEMS];
    int uids_len;

    trace_mode_t pid_mode;
    pid_t pids[MAX_LIST_ITEMS];
    int pids_len;

    trace_mode_t ppid_mode;
    pid_t ppids[MAX_LIST_ITEMS];
    int ppids_len;

    trace_mode_t netio_mode;

    #ifdef USE_BPF_SPIN_LOCK
    #ifdef USERSPACE_CODE
    unsigned int lock;
    #else
    struct bpf_spin_lock lock;
    #endif
    #endif
};