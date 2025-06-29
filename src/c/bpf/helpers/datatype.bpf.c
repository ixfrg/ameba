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
#include "common/version.h"

#include <bpf/bpf_helpers.h>

// externs
extern const struct elem_version record_version;


// extern functions
int datatype_init_elem_version(
    struct elem_version *e_version
)
{
    if (!e_version)
        return 0;
    e_version->major = record_version.major;
    e_version->minor = record_version.minor;
    e_version->patch = record_version.patch;
    return 0;
}

int datatype_init_elem_common(
    struct elem_common *e_common,
    record_type_t record_type
)
{
    if (!e_common)
        return 0;
    e_common->magic = (int)AMEBA_MAGIC;
    e_common->record_type = record_type;
    datatype_init_elem_version(&(e_common->version));

#ifdef INCLUDE_TASK_CTX_ID
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    e_common->task_ctx_id = (task_ctx_id_t)current_task;
#endif
    return 0;
}

int datatype_init_elem_timestamp(
    struct elem_timestamp *e_ts,
    event_id_t event_id
)
{
    if (!e_ts)
        return 0;
    e_ts->event_id = event_id;
    return 0;
}

int datatype_init_elem_sockaddr(
    struct elem_sockaddr *e_sockaddr,
    socklen_t addrlen,
    byte_order_t byte_order
)
{
    if (!e_sockaddr)
        return 0;
    e_sockaddr->addrlen = addrlen;
    e_sockaddr->byte_order = byte_order;
    return 0;
}

int datatype_zero_out_elem_sockaddr(
    struct elem_sockaddr *e_sockaddr
)
{
    if (!e_sockaddr)
        return 0;
    return datatype_init_elem_sockaddr(e_sockaddr, 0, 0);
}

int datatype_init_record_new_process(
    struct record_new_process *r_new_process,
    event_id_t event_id,
    pid_t pid, pid_t ppid, sys_id_t sys_id
)
{
    if (!r_new_process)
        return 0;
    datatype_init_elem_common(&(r_new_process->e_common), RECORD_TYPE_NEW_PROCESS);
    datatype_init_elem_timestamp(&(r_new_process->e_ts), event_id);

    r_new_process->pid = pid;
    r_new_process->ppid = ppid;
    r_new_process->sys_id = sys_id;

    return 0;
}

int datatype_init_record_cred(
    struct record_cred *r_c,
    event_id_t event_id,
    pid_t pid, sys_id_t sys_id
)
{
    if (!r_c)
        return 0;
    datatype_init_elem_common(&(r_c->e_common), RECORD_TYPE_CRED);
    datatype_init_elem_timestamp(&(r_c->e_ts), event_id);

    r_c->pid = pid;
    r_c->sys_id = sys_id;

    return 0;
}

int datatype_init_record_namespace(
    struct record_namespace *r_namespace,
    event_id_t event_id,
    pid_t pid, sys_id_t sys_id
)
{
    if (!r_namespace)
        return 0;
    datatype_init_elem_common(&(r_namespace->e_common), RECORD_TYPE_NAMESPACE);
    datatype_init_elem_timestamp(&(r_namespace->e_ts), event_id);

    r_namespace->pid = pid;
    r_namespace->sys_id = sys_id;

    return 0;
}

int datatype_init_record_connect(
    struct record_connect *r_connect,
    pid_t pid, int fd, int ret
)
{
    if (!r_connect)
        return 0;
    datatype_init_elem_common(&(r_connect->e_common), RECORD_TYPE_CONNECT);
    datatype_init_elem_timestamp(&(r_connect->e_ts), 0);

    r_connect->pid = pid;
    r_connect->fd = fd;
    r_connect->ret = ret;

    return 0;
}

int datatype_zero_out_record_connect(
    struct record_connect *r_connect
)
{
    if (!r_connect)
        return 0;
    datatype_init_record_connect(r_connect, 0, 0, 0);
    r_connect->local.addrlen = 0;
    r_connect->remote.addrlen = 0;
    return 0;
}

int datatype_init_record_send_recv(
   struct record_send_recv *r_send_recv,
    pid_t pid, int fd, ssize_t ret
)
{
    if (!r_send_recv)
        return 0;
    datatype_init_elem_common(&(r_send_recv->e_common), RECORD_TYPE_SEND_RECV);
    datatype_init_elem_timestamp(&(r_send_recv->e_ts), 0);

    r_send_recv->pid = pid;
    r_send_recv->fd = fd;
    r_send_recv->ret = ret;

    return 0;
}

int datatype_zero_out_record_send_recv(
    struct record_send_recv *r_send_recv
)
{
    if (!r_send_recv)
        return 0;
    datatype_init_record_send_recv(r_send_recv, 0, 0, 0);
    r_send_recv->local.addrlen = 0;
    r_send_recv->remote.addrlen = 0;
    return 0;
}

int datatype_init_record_accept(
    struct record_accept *r_accept,
    pid_t pid, int fd
)
{
    if (!r_accept)
        return 0;

    datatype_init_elem_common(&(r_accept->e_common), RECORD_TYPE_ACCEPT);
    datatype_init_elem_timestamp(&(r_accept->e_ts), 0);

    r_accept->pid = pid;
    r_accept->fd = fd;

    return 0;
}

int datatype_zero_out_record_accept(
    struct record_accept *r_accept, sys_id_t sys_id
)
{
    if (!r_accept)
        return 0;
    datatype_init_record_accept(r_accept, 0, 0);
    r_accept->local.addrlen = 0;
    r_accept->remote.addrlen = 0;
    r_accept->sys_id = sys_id;
    return 0;
}

int datatype_init_fd_record_accept(struct record_accept *r_accept, int fd)
{
    if (!r_accept)
        return 0;
    r_accept->fd = fd;
    return 0;
}

int datatype_init_record_bind(
    struct record_bind *r_bind,
    pid_t pid, int fd
)
{
    if (!r_bind)
        return 0;

    datatype_init_elem_common(&(r_bind->e_common), RECORD_TYPE_BIND);
    datatype_init_elem_timestamp(&(r_bind->e_ts), 0);

    r_bind->pid = pid;
    r_bind->fd = fd;

    return 0;
}

int datatype_zero_out_record_bind(
    struct record_bind *r_bind
)
{
    if (!r_bind)
        return 0;
    datatype_init_record_bind(r_bind, 0, 0);
    r_bind->local.addrlen = 0;
    return 0;
}

int datatype_init_record_kill(
    struct record_kill *r_kill, 
    pid_t acting_pid,
    pid_t target_pid, 
    int sig
)
{
    if (!r_kill)
        return 0;

    datatype_init_elem_common(&(r_kill->e_common), RECORD_TYPE_KILL);
    datatype_init_elem_timestamp(&(r_kill->e_ts), 0);

    r_kill->acting_pid = acting_pid;
    r_kill->target_pid = target_pid;
    r_kill->sig = sig;
    r_kill->ret = 0;

    return 0;
}

int datatype_init_record_audit_log_exit(
    struct record_audit_log_exit *r_ale,
    pid_t pid,
    event_id_t event_id,
    int syscall_number
)
{
    if (!r_ale)
        return 0;

    datatype_init_elem_common(&(r_ale->e_common), RECORD_TYPE_AUDIT_LOG_EXIT);
    datatype_init_elem_timestamp(&(r_ale->e_ts), event_id);

    r_ale->pid = pid;
    r_ale->syscall_number = syscall_number;
    return 0;
}