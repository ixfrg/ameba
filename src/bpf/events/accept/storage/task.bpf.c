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
    __type(value, struct record_accept);
} task_map_accept_local SEC(".maps");


struct
{
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct record_accept);
} task_map_accept_remote SEC(".maps");


int accept_storage_insert_local_fd(struct record_accept *map_val)
{
    if (!map_val)
        return 0;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    void *result = bpf_task_storage_get(&task_map_accept_local, current_task, map_val, BPF_LOCAL_STORAGE_GET_F_CREATE);
    return result != NULL;
}

int accept_storage_insert_remote_fd(struct record_accept *map_val)
{
    if (!map_val)
        return 0;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    void *result = bpf_task_storage_get(&task_map_accept_remote, current_task, map_val, BPF_LOCAL_STORAGE_GET_F_CREATE);
    return result != NULL;
}

int accept_storage_set_local_fd_saddrs(struct elem_sockaddr *local, struct elem_sockaddr *remote)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct record_accept *result = bpf_task_storage_get(&task_map_accept_local, current_task, 0, 0);
    if (!result)
        return 0;
    if (local)
        result->local = *local;
    if (remote)
        result->remote = *remote;
    return 1; // Something is set so success
}

int accept_storage_set_remote_fd_saddrs(struct elem_sockaddr *local, struct elem_sockaddr *remote)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct record_accept *result = bpf_task_storage_get(&task_map_accept_remote, current_task, 0, 0);
    if (!result)
        return 0;
    if (local)
        result->local = *local;
    if (remote)
        result->remote = *remote;
    return 1; // Something is set so success
}

int accept_storage_set_local_fd_props_on_sys_exit(pid_t pid, event_id_t event_id)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct record_accept *result = bpf_task_storage_get(&task_map_accept_local, current_task, 0, 0);
    if (!result)
        return 0;
    result->pid = pid;
    result->e_ts.event_id = event_id;
    return 1;
}

int accept_storage_set_remote_fd_props_on_sys_exit(pid_t pid, int ret_fd, event_id_t event_id)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct record_accept *result = bpf_task_storage_get(&task_map_accept_remote, current_task, 0, 0);
    if (!result)
        return 0;
    result->pid = pid;
    result->fd = ret_fd;
    result->e_ts.event_id = event_id;
    return 1;
}

int accept_storage_delete_local_fd(void)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    return bpf_task_storage_delete(&task_map_accept_local, current_task);
}

int accept_storage_delete_remote_fd(void)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    return bpf_task_storage_delete(&task_map_accept_remote, current_task);
}

int accept_storage_delete_both_fds(void)
{
    accept_storage_delete_local_fd();
    accept_storage_delete_remote_fd();
    return 0;
}

int accept_storage_output_local_fd(void)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct record_accept *result = bpf_task_storage_get(&task_map_accept_local, current_task, 0, 0);
    if (!result)
        return 0;
    output_record_accept(result);
    return 0;
}

int accept_storage_output_remote_fd(void)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct record_accept *result = bpf_task_storage_get(&task_map_accept_remote, current_task, 0, 0);
    if (!result)
        return 0;
    output_record_accept(result);
    return 0;
}