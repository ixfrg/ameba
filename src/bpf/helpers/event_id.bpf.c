#include "common/vmlinux.h"
#include "common/types.h"

#include "bpf/helpers/log.bpf.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>


static event_id_t current_event_id = 0;


struct
{
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, event_id_t);
} task_map_event_id SEC(".maps");


event_id_t event_id_increment(void)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    // return BPF_CORE_READ(current_task, audit_context, stamp).serial;
    event_id_t e_id = __sync_fetch_and_add(&current_event_id, 1);
    void *result = bpf_task_storage_get(&task_map_event_id, current_task, &e_id, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!result)
    {
        LOG_WARN("Failed to insert current event id into task map for event id");
    }
    return e_id;
}

int event_id_get_last_from_task_map(event_id_t *event_id)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    event_id_t *result = bpf_task_storage_get(&task_map_event_id, current_task, NULL, 0);
    if (result != NULL && event_id != NULL)
    {
        *event_id = *result;
        return 1;
    }
    return 0;
}