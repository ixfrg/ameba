#pragma once

#include "common/vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "common/vmlinux.h"
#include "common/types.h"
#include "common/control.h"


struct event_context {
    int use_global_control_input;
    record_type_t record_type;
};


event_id_t event_increment_id(void);
int event_is_auditable(struct event_context *e_ctx);
int event_init_context(struct event_context *e_ctx, record_type_t r_type);
int event_is_netio_set_to_ignore(void);


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