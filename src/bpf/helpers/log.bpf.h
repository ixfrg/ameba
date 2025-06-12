#pragma once

/*

    A module for defining helper functions for logging.

*/

#include "common/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "common/control.h"


// Log prefix.
#define LOG_PREFIX "[ameba] [bpf]"

// Macros for using bpf_printk in a uniform way.
#define LOG_WARN(fmt, args...) bpf_printk("%s" "[WARN]" fmt "\n", LOG_PREFIX, ##args)
#define LOG_ERROR(fmt, args...) bpf_printk("%s" "[ERROR]" fmt "\n", LOG_PREFIX, ##args)

/*
    Log interpreted value of trace mode.

    Return:
        0 -> Always
*/
int log_trace_mode(char *key, trace_mode_t t);

/*
    Log interpreted value of control lock with key.

    Return:
        0 -> Always
*/
int log_control_lock(char *key, control_lock_t t);

/*
    Log control_input.

    Return:
        0 -> Always
*/
int log_control_input(struct control_input *ctrl);