#pragma once

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