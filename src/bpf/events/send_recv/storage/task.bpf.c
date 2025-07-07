// SPDX-License-Identifier: GPL-3.0-or-later
/*
AMEBA - A Minimal eBPF-based Audit: an eBPF-based Linux telemetry collection tool.
Copyright (C) 2025  Hassaan Irshad

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "common/vmlinux.h"

#include "common/types.h"
#include "bpf/helpers/output.bpf.h"
#include "bpf/helpers/log.bpf.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>


struct
{
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct record_send_recv);
} task_map_send_recv SEC(".maps");


int send_recv_storage_insert(struct record_send_recv *map_val)
{
    if (!map_val)
        return 0;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    void *result = bpf_task_storage_get(&task_map_send_recv, current_task, map_val, BPF_LOCAL_STORAGE_GET_F_CREATE);
    return result != NULL;
}

int send_recv_storage_delete(void)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    return bpf_task_storage_delete(&task_map_send_recv, current_task);
}

int send_recv_storage_set_saddrs(inode_num_t net_ns_inum, short int sock_type, struct elem_sockaddr *local, struct elem_sockaddr *remote)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct record_send_recv *result = bpf_task_storage_get(&task_map_send_recv, current_task, 0, 0);
    if (!result)
        return 0;
    result->ns_net = net_ns_inum;
    result->sock_type = sock_type;
    if (local)
        result->local = *local;
    if (remote)
        result->remote = *remote;
    return 1; // Something is set so success
}

int send_recv_storage_set_props_on_sys_exit(pid_t pid, int fd, ssize_t ret, event_id_t event_id)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct record_send_recv *result = bpf_task_storage_get(&task_map_send_recv, current_task, 0, 0);
    if (!result)
        return 0;
    result->pid = pid;
    result->fd = fd;
    result->ret = ret;
    result->e_ts.event_id = event_id;
    return 1;
}

int send_recv_storage_output(void)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct record_send_recv *result = bpf_task_storage_get(&task_map_send_recv, current_task, NULL, 0);
    if (!result)
        return 0;
    output_record_send_recv(result);
    return 0;
}