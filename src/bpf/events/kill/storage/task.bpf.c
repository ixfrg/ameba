#include "common/vmlinux.h"

#include "common/types.h"
#include "bpf/helpers/output.bpf.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>


struct
{
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct record_kill);
} task_map_kill SEC(".maps");


int kill_storage_insert(struct record_kill *map_val)
{
    if (!map_val)
        return 0;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    void *result = bpf_task_storage_get(&task_map_kill, current_task, map_val, BPF_LOCAL_STORAGE_GET_F_CREATE);
    return result != NULL;
}

int kill_storage_delete(void)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    return bpf_task_storage_delete(&task_map_kill, current_task);
}

int kill_storage_set_props_on_sys_exit(int ret, event_id_t event_id)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct record_kill *result = bpf_task_storage_get(&task_map_kill, current_task, NULL, 0);
    if (!result)
        return 0;
    result->ret = ret;
    result->e_ts.event_id = event_id;
    return 0;
}

pid_t kill_storage_get_target_pid()
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct record_kill *result = bpf_task_storage_get(&task_map_kill, current_task, NULL, 0);
    if (!result)
        return 0; // TODO... dual meaning i.e. 0 can be considered a valid pid value by the caller
    return result->target_pid;
}

int kill_storage_output(void)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct record_kill *result = bpf_task_storage_get(&task_map_kill, current_task, NULL, 0);
    if (!result)
        return 0;
    output_record_kill(result);
    return 0;
}