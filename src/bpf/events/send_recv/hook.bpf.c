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
#include "bpf/events/send_recv/storage.bpf.h"


static int insert_send_recv_map_entry_at_syscall_enter(sys_id_t sys_id)
{
    struct record_send_recv map_val;
    datatype_zero_out_record_send_recv(&map_val);
    map_val.sys_id = sys_id;

    if (!send_recv_storage_insert(&map_val))
    {
        LOG_WARN("[insert_send_recv_map_entry_at_syscall_enter] Failed to do map insert.");
    }

    return 0;
}

static int delete_send_recv_map_entry(void)
{
    send_recv_storage_delete();

    return 0;
}

static int update_send_recv_map_entry_with_local_saddr(struct socket *sock)
{

    if (!sock)
    {
        delete_send_recv_map_entry();
        return 0;
    }

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
        // possible_net_t skc_net = sk_c.skc_net;
        // struct net *net_ns = skc_net.net;
        // struct ns_common ns = BPF_CORE_READ(net_ns, ns);
        // inode_num_t net_ns_inum = ns.inum;
        inode_num_t net_ns_inum;
        copy_net_ns_inum_from_current_task(&net_ns_inum);
        short int sock_type = (short int)BPF_CORE_READ(sock, type);
        send_recv_storage_set_saddrs(
            net_ns_inum,
            sock_type,
            &local, &remote
        );
    }

    return 0;
}

static int update_send_recv_map_entry_on_syscall_exit(
    int fd, struct sockaddr *addr, int addrlen, ssize_t ret
)
{
    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    const pid_t pid = BPF_CORE_READ(current_task, pid);

    send_recv_storage_set_props_on_sys_exit(pid, fd, ret, event_id_increment());

    // Shouldn't have to do the following since we got it from another hook
    // if (addr)
    // {
    //     // Sometimes NULL like in send/sendmsg syscall.
    //     struct elem_sockaddr *remote_sa = (struct elem_sockaddr *)&(map_val->remote);
    //     remote_sa->byte_order = BYTE_ORDER_NETWORK;
    //     remote_sa->addrlen = addrlen & (SOCKADDR_MAX_SIZE - 1);
    //     bpf_probe_read_user(&(remote_sa->addr[0]), remote_sa->addrlen, addr);
    // }

    return 0;
}

static int send_send_recv_map_entry_on_syscall_exit(void)
{
    send_recv_storage_output();
    return 0;
}

// Begin syscall sys_sendto 
// hooks
int AMEBA_HOOK(
    "fentry/__sys_sendto",
    fentry__sys_sendto,
    RECORD_TYPE_SEND_RECV
)
{
    insert_send_recv_map_entry_at_syscall_enter(SYS_ID_SENDTO);
    return 0;
}

int AMEBA_HOOK(
    "fexit/__sys_sendto",
    fexit__sys_sendto,
    RECORD_TYPE_SEND_RECV,
    int fd, 
    void *buff, 
    size_t len, 
    unsigned int flags,
	struct sockaddr *addr,
    int addr_len,
    ssize_t ret
)
{
    if (ret < 0)
    {
        delete_send_recv_map_entry();
        return 0;
    }
    update_send_recv_map_entry_on_syscall_exit(fd, addr, addr_len, ret);
    send_send_recv_map_entry_on_syscall_exit();
    delete_send_recv_map_entry();
    return 0;
}
// End syscall sys_sendto

// Begin syscall sys_sendmsg
// hooks
int AMEBA_HOOK(
    "fentry/__sys_sendmsg",
    fentry__sys_sendmsg,
    RECORD_TYPE_SEND_RECV
)
{
    insert_send_recv_map_entry_at_syscall_enter(SYS_ID_SENDMSG);
    return 0;
}

int AMEBA_HOOK(
    "fexit/__sys_sendmsg",
    fexit__sys_sendmsg,
    RECORD_TYPE_SEND_RECV,
    int fd, 
    struct user_msghdr *msg, 
    unsigned int flags,
	bool forbid_cmsg_compat,
    long ret
)
{
    if (ret < 0)
    {
        delete_send_recv_map_entry();
        return 0;
    }

    struct sockaddr *addr = NULL;
    int addrlen = 0;
    if (msg)
    {
        addr = (struct sockaddr *)BPF_CORE_READ(msg, msg_name);
        addrlen = BPF_CORE_READ(msg, msg_namelen);
    }
    update_send_recv_map_entry_on_syscall_exit(fd, addr, addrlen, ret);
    send_send_recv_map_entry_on_syscall_exit();
    delete_send_recv_map_entry();
    return 0;
}
// End syscall sys_sendmsg

// Begin syscall sys_recvfrom
// hooks
int AMEBA_HOOK(
    "fentry/__sys_recvfrom",
    fentry__sys_recvfrom,
    RECORD_TYPE_SEND_RECV
)
{
    insert_send_recv_map_entry_at_syscall_enter(SYS_ID_RECVFROM);
    return 0;
}

int AMEBA_HOOK(
    "fexit/__sys_recvfrom",
    fexit__sys_recvfrom,
    RECORD_TYPE_SEND_RECV,
    int fd, 
    void *buff, 
    size_t len, 
    unsigned int flags,
	struct sockaddr *addr,
    int addr_len,
    ssize_t ret
)
{
    if (ret < 0)
    {
        delete_send_recv_map_entry();
        return 0;
    }
    update_send_recv_map_entry_on_syscall_exit(fd, addr, addr_len, ret);
    send_send_recv_map_entry_on_syscall_exit();
    delete_send_recv_map_entry();
    return 0;
}
// End syscall sys_recvfrom

// Begin syscall sys_recvmsg
// hooks
int AMEBA_HOOK(
    "fentry/__sys_recvmsg",
    fentry__sys_recvmsg,
    RECORD_TYPE_SEND_RECV
)
{
    insert_send_recv_map_entry_at_syscall_enter(SYS_ID_RECVMSG);
    return 0;
}

int AMEBA_HOOK(
    "fexit/__sys_recvmsg",
    fexit__sys_recvmsg,
    RECORD_TYPE_SEND_RECV,
    int fd, 
    struct user_msghdr *msg, 
    unsigned int flags,
    long ret
)
{
    if (ret < 0)
    {
        delete_send_recv_map_entry();
        return 0;
    }

    struct sockaddr *addr = NULL;
    int addrlen = 0;
    if (msg)
    {
        addr = (struct sockaddr *)BPF_CORE_READ(msg, msg_name);
        addrlen = BPF_CORE_READ(msg, msg_namelen);
    }
    update_send_recv_map_entry_on_syscall_exit(fd, addr, addrlen, ret);
    send_send_recv_map_entry_on_syscall_exit();
    delete_send_recv_map_entry();
    return 0;
}
// End syscall sys_recvmsg

// Intermediate state update functions
int AMEBA_HOOK(
    "fexit/sock_sendmsg",
    fexit__sock_sendmsg,
    RECORD_TYPE_SEND_RECV,
    struct socket *sock,
    struct msghdr *msg,
    int ret
)
{
    if (ret < 0)
    {
        delete_send_recv_map_entry();
        return 0;
    }

    update_send_recv_map_entry_with_local_saddr(sock);

    return 0;
}

int AMEBA_HOOK(
    "fexit/sock_recvmsg",
    fexit__sock_recvmsg,
    RECORD_TYPE_SEND_RECV,
    struct socket *sock,
    struct msghdr *msg,
    int flags,
    int ret
)
{
    if (ret < 0)
    {
        delete_send_recv_map_entry();
        return 0;
    }

    update_send_recv_map_entry_with_local_saddr(sock);

    return 0;
}