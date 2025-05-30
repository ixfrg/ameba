#include "common/vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "bpf/ameba.bpf.h"
#include "common/types.h"
#include "bpf/helpers/log.bpf.h"


// special
char _license[] SEC("license") = "GPL";


// local globals
static event_id_t current_event_id = 0;


// extern functions
event_id_t ameba_increment_event_id(void)
{
    return __sync_fetch_and_add(&current_event_id, 1);
}

int ameba_is_event_auditable(struct event_context *e_ctx)
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

