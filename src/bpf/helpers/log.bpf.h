#pragma once

#include "common/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "common/control.h"


// Macros
#define LOG_PREFIX "[ameba] [bpf]"
#define LOG_WARN(fmt, args...) bpf_printk("%s" "[WARN]" fmt "\n", LOG_PREFIX, ##args)
#define LOG_ERROR(fmt, args...) bpf_printk("%s" "[ERROR]" fmt "\n", LOG_PREFIX, ##args)

int log_trace_mode(char *key, trace_mode_t t);
int log_control_lock(char *key, control_lock_t t);
int log_control_input(struct control_input *ctrl);