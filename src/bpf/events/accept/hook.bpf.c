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

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "common/types.h"
#include "bpf/helpers/log.bpf.h"
#include "bpf/helpers/map.bpf.h"
#include "bpf/helpers/event.bpf.h"
#include "bpf/helpers/event_id.bpf.h"
#include "bpf/helpers/datatype.bpf.h"
#include "bpf/helpers/copy.bpf.h"
#include "bpf/helpers/output.bpf.h"
#include "bpf/events/accept/storage.bpf.h"


// defs
typedef enum {
    LOCAL = 1,
    REMOTE = 2
} accept_type_fd_t;


// local globals
static const record_type_t accept_record_type = RECORD_TYPE_ACCEPT;

/*
static int insert_accept_local_map_entry_at_syscall_enter(sys_id_t sys_id, int fd)
{
    struct record_accept map_val;
    datatype_zero_out_record_accept(&map_val, sys_id);
    datatype_init_fd_record_accept(&map_val, fd);

    if (!accept_storage_insert_local_fd(&map_val))
    {
        LOG_WARN("[insert_accept_local_map_entry_at_syscall_enter] Failed to insert map entry for local fd");
    }

    return 0;
}
*/
static int insert_accept_remote_map_entry_at_syscall_enter(sys_id_t sys_id, int fd)
{
    struct record_accept map_val;
    datatype_zero_out_record_accept(&map_val, sys_id);
    datatype_init_fd_record_accept(&map_val, fd);

    if (!accept_storage_insert_remote_fd(&map_val))
    {
        LOG_WARN("[insert_accept_remote_map_entry_at_syscall_enter] Failed to insert map entry for remote fd");
    }
    return 0;
}

static int update_accept_map_entry_with_file(accept_type_fd_t fd_type, struct file *file)
{
    if (!file){
        return 0;
    }

    struct socket *sock = bpf_sock_from_file(file);
    if (sock) {
        int sockaddrs_are_set = 0;
        struct elem_sockaddr local, remote;

        struct sock_common sk_c = BPF_CORE_READ(sock, sk, __sk_common);
        if (sk_c.skc_family == AF_INET) {
            copy_sockaddr_in_local_from_skc(&(local), &sk_c);
            copy_sockaddr_in_remote_from_skc(&(remote), &sk_c);
            sockaddrs_are_set = 1;
        } else if (sk_c.skc_family == AF_INET6) {
            copy_sockaddr_in6_local_from_skc(&(local), &sk_c);
            copy_sockaddr_in6_remote_from_skc(&(remote), &sk_c);
            sockaddrs_are_set = 1;
        }

        if (sockaddrs_are_set)
        {
            inode_num_t net_ns_inum;
            copy_net_ns_inum_from_current_task(&net_ns_inum);
            short int sock_type = (short int)BPF_CORE_READ(sock, type);

            if (fd_type == LOCAL)
            {
                // accept_storage_set_local_fd_saddrs(net_ns_inum, sock_type, &local, &remote);
            } else if (fd_type == REMOTE)
            {
                accept_storage_set_remote_fd_saddrs(net_ns_inum, sock_type, &local, &remote);
            }
        }
    }
    return 0;
}

static int sys_accept_enter(sys_id_t sys_id, int fd)
{
    // insert_accept_local_map_entry_at_syscall_enter(sys_id, fd);
    insert_accept_remote_map_entry_at_syscall_enter(sys_id, fd);
    return 0;
}

static int sys_accept_exit(int ret_fd)
{
    if (ret_fd == -1)
    {
        accept_storage_delete_both_fds();
        return 0;
    }

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    const pid_t pid = BPF_CORE_READ(current_task, pid);

    event_id_t event_id = event_id_increment();

    // accept_storage_set_local_fd_props_on_sys_exit(pid, event_id);
    accept_storage_set_remote_fd_props_on_sys_exit(pid, ret_fd, event_id);

    // accept_storage_output_local_fd();
    accept_storage_output_remote_fd();

    accept_storage_delete_both_fds();

    return 0;
}

struct proto_accept_arg;
int AMEBA_HOOK(
    "fexit/do_accept", 
    fexit__do_accept, 
    accept_record_type, 
    struct file *file,
    struct proto_accept_arg *arg,
	struct sockaddr *upeer_sockaddr,
	int *upeer_addrlen,
    int flags,
    struct file *ret_file
)
{
    if (!ret_file){
        accept_storage_delete_both_fds();
        return 0;
    }

    update_accept_map_entry_with_file(LOCAL, file);
    update_accept_map_entry_with_file(REMOTE, ret_file);

    return 0;
}

int AMEBA_HOOK_TP(
    "tracepoint/syscalls/sys_enter_accept",
    trace_accept_enter,
    accept_record_type,
    struct trace_event_raw_sys_enter *, sys_ctx
)
{
    int fd = BPF_CORE_READ(sys_ctx, args[0]);
    sys_accept_enter(SYS_ID_ACCEPT, fd);
    return 0;
}

int AMEBA_HOOK_TP(
    "tracepoint/syscalls/sys_enter_accept4",
    trace_accept4_enter,
    accept_record_type,
    struct trace_event_raw_sys_enter *, sys_ctx
)
{
    int fd = BPF_CORE_READ(sys_ctx, args[0]);
    sys_accept_enter(SYS_ID_ACCEPT4, fd);
    return 0;
}

int AMEBA_HOOK_TP(
    "tracepoint/syscalls/sys_exit_accept",
    trace_accept_exit,
    accept_record_type,
    struct trace_event_raw_sys_exit *, sys_ctx
)
{
    int ret_fd = BPF_CORE_READ(sys_ctx, ret);
    sys_accept_exit(ret_fd);
    return 0;
}

int AMEBA_HOOK_TP(
    "tracepoint/syscalls/sys_exit_accept4",
    trace_accept4_exit,
    accept_record_type,
    struct trace_event_raw_sys_exit *, sys_ctx
)
{
    int ret_fd = BPF_CORE_READ(sys_ctx, ret);
    sys_accept_exit(ret_fd);
    return 0;
}