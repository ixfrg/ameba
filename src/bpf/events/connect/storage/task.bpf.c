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
    __type(value, struct record_connect);
} task_map_connect SEC(".maps");


int connect_storage_insert(struct record_connect *map_val)
{
    if (!map_val)
        return 0;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    void *result = bpf_task_storage_get(&task_map_connect, current_task, map_val, BPF_LOCAL_STORAGE_GET_F_CREATE);
    return result != NULL;
}

int connect_storage_set_sock_type_net_ns(short int sock_type, inode_num_t net_ns)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct record_connect *result = bpf_task_storage_get(&task_map_connect, current_task, NULL, 0);
    if (!result)
        return 0;
    result->sock_type = sock_type;
    result->ns_net = net_ns;
    return 1;
}

int connect_storage_delete(void)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    return bpf_task_storage_delete(&task_map_connect, current_task);
}

int connect_storage_set_props_on_sys_exit(pid_t pid, int fd, int ret, event_id_t event_id)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct record_connect *result = bpf_task_storage_get(&task_map_connect, current_task, NULL, 0);
    if (!result)
        return 0;
    result->pid = pid;
    result->fd = fd;
    result->ret = ret;
    result->e_ts.event_id = event_id;
    return 0;
}

int connect_storage_set_local(struct elem_sockaddr *local)
{
    if (!local)
        return 0;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct record_connect *result = bpf_task_storage_get(&task_map_connect, current_task, NULL, 0);
    if (!result)
        return 0;
    result->local = *local;
    return 0;
}

int connect_storage_set_remote(struct elem_sockaddr *remote)
{
    if (!remote)
        return 0;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct record_connect *result = bpf_task_storage_get(&task_map_connect, current_task, NULL, 0);
    if (!result)
        return 0;
    result->remote = *remote;
    return 0;
}

int connect_storage_output(void)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct record_connect *result = bpf_task_storage_get(&task_map_connect, current_task, NULL, 0);
    if (!result)
        return 0;
    output_record_connect(result);
    return 0;
}