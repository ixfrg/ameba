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

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>


struct
{
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct record_bind);
} task_map_bind SEC(".maps");


int bind_storage_insert(struct record_bind *r_bind)
{
    if (!r_bind)
        return 0;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    void *result = bpf_task_storage_get(&task_map_bind, current_task, r_bind, BPF_LOCAL_STORAGE_GET_F_CREATE);
    return result != NULL;
}

int bind_storage_set(int fd, event_id_t event_id, struct elem_sockaddr *local_sa)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct record_bind *result = bpf_task_storage_get(&task_map_bind, current_task, 0, 0);
    if (!result)
        return 0;
    result->fd = fd;
    result->e_ts.event_id = event_id;
    if (local_sa)
        result->local = *local_sa;
    return 1;
}

int bind_storage_output(void)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct record_bind *result = bpf_task_storage_get(&task_map_bind, current_task, 0, 0);
    if (!result)
        return 0;
    output_record_bind(result);
    return 0;
}

int bind_storage_delete(void)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    return bpf_task_storage_delete(&task_map_bind, current_task);
}