#include "bpf/helpers/event_context.bpf.h"


int event_context_init_event_context(struct event_context *e_ctx, record_type_t r_type)
{
    if (!e_ctx)
        return 0;
    e_ctx->record_type = r_type;
    return 0;
}