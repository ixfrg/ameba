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

#include "bpf/helper/log.bpf.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>


static event_id_t current_event_id = 0;

/*
struct
{
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, event_id_t);
} AMEBA_MAP_NAME(task_map_event_id) SEC(".maps");
*/

/*
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
*/

/*
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
*/

event_id_t event_id_increment(void)
{
    return __sync_fetch_and_add(&current_event_id, 1);
}