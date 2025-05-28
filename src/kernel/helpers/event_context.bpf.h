#pragma once

#include "common/vmlinux.h"
#include "common/types.h"


struct event_context {
    record_type_t record_type;
};


int event_context_init_event_context(struct event_context *e_ctx, record_type_t r_type);