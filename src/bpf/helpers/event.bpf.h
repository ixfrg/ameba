#pragma once

/*

    A module for defining helper functions for event filter and hooking.

*/

#include "common/vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "common/vmlinux.h"
#include "common/types.h"
#include "common/control.h"


/*
    Struct to define common per-event context when event is triggered.

    Used for event filtering decision making.
*/
struct event_context {
    int use_global_control_input;
    record_type_t record_type;
};

/*
    Consult the control_input (global) and event context to check if the
    event is auditable.

    Return:
        0 => The event is not auditable.
        1 => The event is auditable.
*/
int event_is_auditable(struct event_context *e_ctx);

/*
    Initialize the event context with r_type.

    It also, transparently, initializes the global control_input if not already done so.

    Return:
        0 => Always.
*/
int event_init_context(struct event_context *e_ctx, record_type_t r_type);

/*
    Check whether network IO is set to true/false.

    Return:
        0 -> False
        1 -> True
*/
int event_is_netio_set_to_ignore(void);


/*
    A macro that combines the following into one macro:

    1. Add SEC(sec_name).
    2. Check if event_is_auditable.
    3. Use BPF_PROG to unmarshall arguments.
*/
#define AMEBA_HOOK(sec_name, f_name, record_type, args...) \
__ameba__##f_name(unsigned long long *ctx); \
static __always_inline typeof(__ameba__##f_name(0)) __ameba__bpf__##f_name(unsigned long long *ctx); \
SEC(sec_name) \
typeof(__ameba__##f_name(0)) \
__ameba__##f_name(unsigned long long *ctx)				    \
{									    \
    struct event_context e_ctx; \
    event_init_context(&e_ctx, record_type); \
    if (!event_is_auditable(&e_ctx)) { \
        return 0; \
    } \
	return __ameba__bpf__##f_name(ctx);			    \
}	\
typeof(__ameba__##f_name(0)) \
BPF_PROG(__ameba__bpf__##f_name, ##args)


/*
    A macro that combines the following into one macro:

    1. Add SEC(sec_name).
    2. Check if event_is_auditable.
    3. Use (ctx_struct_type, ctx_arg_name) to pass BPF context to hook function.
*/
#define AMEBA_HOOK_TP(sec_name, f_name, record_type, ctx_struct_type, ctx_arg_name) \
__ameba__##f_name(ctx_struct_type ctx_arg_name); \
static __always_inline typeof(__ameba__##f_name(0)) __ameba__bpf__##f_name(ctx_struct_type ctx_arg_name); \
SEC(sec_name) \
typeof(__ameba__##f_name(0)) \
__ameba__##f_name(ctx_struct_type ctx_arg_name)				    \
{									    \
    struct event_context e_ctx; \
    event_init_context(&e_ctx, record_type); \
    if (!event_is_auditable(&e_ctx)) { \
        return 0; \
    } \
	return __ameba__bpf__##f_name(ctx_arg_name);			    \
}	\
typeof(__ameba__##f_name(0)) \
__ameba__bpf__##f_name(ctx_struct_type ctx_arg_name)