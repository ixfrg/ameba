#include "common/vmlinux.h"
#include "common/types.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>


static event_id_t current_event_id = 0;


event_id_t event_id_increment(void)
{
    // struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    // return BPF_CORE_READ(current_task, audit_context, stamp).serial;
    return __sync_fetch_and_add(&current_event_id, 1);
}