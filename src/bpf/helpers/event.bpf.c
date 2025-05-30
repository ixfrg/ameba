#include "bpf/helpers/event.bpf.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

static event_id_t current_event_id = 0;


int event_init_context(struct event_context *e_ctx, record_type_t r_type)
{
    if (!e_ctx)
        return 0;
    e_ctx->record_type = r_type;
    return 0;
}

event_id_t event_increment_id(void)
{
    return __sync_fetch_and_add(&current_event_id, 1);
}

int event_is_auditable(struct event_context *e_ctx)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    uid_t uid = BPF_CORE_READ(current_task, real_cred, uid).val;
    // "uid=1001(audited_user) gid=1001(audited_user) groups=1001(audited_user),100(users)"
    // if (record_type == RECORD_TYPE_NAMESPACE)
    // {
    //     return uid == 0;
    // }
    return uid == 1001;
}