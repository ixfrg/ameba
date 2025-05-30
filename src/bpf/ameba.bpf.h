#pragma once


#include "bpf/helpers/event_context.bpf.h"


event_id_t ameba_increment_event_id(void);
int ameba_is_event_auditable(struct event_context *e_ctx);

