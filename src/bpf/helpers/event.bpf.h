#pragma once

#include "common/vmlinux.h"
#include "common/types.h"


struct event_context {
    record_type_t record_type;
};


event_id_t event_increment_id(void);
int event_is_auditable(struct event_context *e_ctx);
int event_init_context(struct event_context *e_ctx, record_type_t r_type);