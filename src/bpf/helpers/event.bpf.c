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

#include "bpf/helpers/event.bpf.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include <asm/unistd.h>

#include "bpf/helpers/log.bpf.h"
#include "common/control.h"


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct control_input);
    __uint(max_entries, 1);
} AMEBA_MAP_NAME_CONTROL_INPUT SEC(".maps");
static void *control_input_map = &AMEBA_MAP_NAME_CONTROL_INPUT;


struct
{
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct control_input);
} AMEBA_MAP_NAME(control_input_map_per_task) SEC(".maps");
static void *control_input_map_per_task = &AMEBA_MAP_NAME(control_input_map_per_task);


int event_init_context(struct event_context *e_ctx, record_type_t r_type)
{
    if (!e_ctx)
        return 0;

    e_ctx->record_type = r_type;

    int key = 0;
    struct control_input *control_input_ptr = bpf_map_lookup_elem(control_input_map, &key);
    if (control_input_ptr)
    {
        struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
        void *task_control_input_ptr = bpf_task_storage_get(
            control_input_map_per_task, current_task, control_input_ptr, BPF_LOCAL_STORAGE_GET_F_CREATE
        );
        if (task_control_input_ptr)
        {
            __builtin_memcpy(task_control_input_ptr, control_input_ptr, sizeof(struct control_input));
        } else
        {
            LOG_ERROR("Failed to allocation per task for control input");
        }

        // TODO: Find an approp. location for this.
        // log_control_input(&global_control_input);
    }

    return 0;
}

static int is_int_in_control_input_id_list(int needle, int *haystack, const int haystack_len)
{
    for (int i = 0; i < haystack_len; i++)
    {
        if (haystack[i] == needle)
            return 1;
    }
    return 0;
}

static int is_task_auditable(struct task_struct *current, struct control_input *runtime_control)
{
    if (!current || !runtime_control)
    {
        return 0;
    }
    
    const uid_t uid = BPF_CORE_READ(current, real_cred, uid).val;
    const pid_t pid = BPF_CORE_READ(current, pid);
    const pid_t ppid = BPF_CORE_READ(current, real_parent, pid);

    int is_uid_in_list = is_int_in_control_input_id_list(
        uid, &(runtime_control->uids[0]), (runtime_control->uids_len & (MAX_LIST_ITEMS - 1))
    );
    int is_pid_in_list = is_int_in_control_input_id_list(
        pid, &(runtime_control->pids[0]), (runtime_control->pids_len & (MAX_LIST_ITEMS - 1))
    );
    int is_ppid_in_list = is_int_in_control_input_id_list(
        ppid, &(runtime_control->ppids[0]), (runtime_control->ppids_len & (MAX_LIST_ITEMS - 1))
    );

    if (runtime_control->uid_mode == IGNORE)
    {
        if (is_uid_in_list)
            return 0;
    }
    if (runtime_control->uid_mode == CAPTURE)
    {
        if (!is_uid_in_list)
            return 0;
    }

    if (runtime_control->pid_mode == IGNORE)
    {
        if (is_pid_in_list)
            return 0;
    }
    if (runtime_control->pid_mode == CAPTURE)
    {
        if (!is_pid_in_list)
            return 0;
    }

    if (runtime_control->ppid_mode == IGNORE)
    {
        if (is_ppid_in_list)
            return 0;
    }
    if (runtime_control->ppid_mode == CAPTURE)
    {
        if (!is_ppid_in_list)
            return 0;
    }

    // We audit if have escaped all kill paths above.
    return 1;
}

int is_record_of_type_network_io(record_type_t t)
{
    switch(t)
    {
        case RECORD_TYPE_SEND_RECV:
            return 1;
        default:
            return 0;
    }
}

int is_record_of_type_audit_log_exit(record_type_t t)
{
    switch(t)
    {
        case RECORD_TYPE_AUDIT_LOG_EXIT:
            return 1;
        default:
            return 0;
    }
}

int event_is_netio_set_to_ignore(struct control_input *runtime_control)
{
    if (!runtime_control)
        return 0;
    return runtime_control->netio_mode == IGNORE;
}

static int is_audit_log_exit_syscall_auditable(struct task_struct *current_task, struct control_input *runtime_control)
{
    if (!current_task)
        return 0;

    if (!runtime_control)
        return 0;

    struct audit_context *audit_context = BPF_CORE_READ(current_task, audit_context);

    if (!audit_context)
        return 0;

    long ret = BPF_CORE_READ(audit_context, return_code);

    int syscall_number = BPF_CORE_READ(audit_context, major);

    switch (syscall_number)
    {
        case __NR_accept:
        case __NR_accept4:
        case __NR_bind:
        case __NR_kill:
        case __NR_setns:
        case __NR_unshare:
        case __NR_clone:
        case __NR_clone3:
#ifdef HAVE_DECL___NR_FORK
        case __NR_fork:
#endif
#ifdef HAVE_DECL___NR_VFORK
        case __NR_vfork:
#endif
            return 1;
        case __NR_connect:
            if (ret == 0 || ret == ERROR_EINPROGRESS)
                return 1;
            else
                return 0; //do not log
        case __NR_sendmsg:
        case __NR_sendto:
        case __NR_recvmsg:
        case __NR_recvfrom:
            if (event_is_netio_set_to_ignore(runtime_control))
                return 0; // do not log
            return 1;
        default:
            return 0; // do not log
    }
}

int event_is_auditable(struct event_context *e_ctx)
{
    if (!e_ctx)
        return 0;

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();

    struct control_input *ci = bpf_task_storage_get(
        control_input_map_per_task, current_task, 0, 0
    );
    if (!ci)
        return 0;

    trace_mode_t global_mode = ci->global_mode;
    if (global_mode == IGNORE)
        return 0;

    if (is_record_of_type_network_io(e_ctx->record_type))
    {
        if (ci->netio_mode == IGNORE)
            return 0;
    }

    if (is_record_of_type_audit_log_exit(e_ctx->record_type))
    {
        if (is_audit_log_exit_syscall_auditable(current_task, ci) == 0)
            return 0;
    }

    return is_task_auditable(current_task, ci);
}