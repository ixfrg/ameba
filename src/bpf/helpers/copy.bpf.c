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

#include "bpf/helpers/copy.bpf.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>


int copy_sockaddr_in_local_from_skc(struct elem_sockaddr *dst, struct sock_common *sk_c)
{
    if (!dst || !sk_c)
        return 0;
    
    dst->byte_order = BYTE_ORDER_HOST;
    dst->addrlen = sizeof(struct sockaddr_in);

    struct sockaddr_in *sin = (struct sockaddr_in *)(&dst->addr);
    sin->sin_family = BPF_CORE_READ(sk_c, skc_family);
    sin->sin_port = BPF_CORE_READ(sk_c, skc_num);
    sin->sin_addr.s_addr = BPF_CORE_READ(sk_c, skc_rcv_saddr);

    return 0;
}

int copy_sockaddr_in_remote_from_skc(struct elem_sockaddr *dst, struct sock_common *sk_c)
{
    if (!dst || !sk_c)
        return 0;

    dst->byte_order = BYTE_ORDER_NETWORK;
    dst->addrlen = sizeof(struct sockaddr_in);

    struct sockaddr_in *sin = (struct sockaddr_in *)(&dst->addr);
    sin->sin_family = BPF_CORE_READ(sk_c, skc_family);
    sin->sin_port = BPF_CORE_READ(sk_c, skc_dport);
    sin->sin_addr.s_addr = BPF_CORE_READ(sk_c, skc_daddr);

    return 0;
}

int copy_sockaddr_in6_local_from_skc(struct elem_sockaddr *dst, struct sock_common *sk_c)
{
    if (!dst || !sk_c)
        return 0;

    dst->byte_order = BYTE_ORDER_HOST;
    dst->addrlen = sizeof(struct sockaddr_in6);

    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)(&dst->addr);
    sin6->sin6_family = BPF_CORE_READ(sk_c, skc_family);
    sin6->sin6_port = BPF_CORE_READ(sk_c, skc_num);
    sin6->sin6_addr = BPF_CORE_READ(sk_c, skc_v6_rcv_saddr);

    return 0;
}

int copy_sockaddr_in6_remote_from_skc(struct elem_sockaddr *dst, struct sock_common *sk_c)
{
    if (!dst || !sk_c)
        return 0;

    dst->byte_order = BYTE_ORDER_NETWORK;
    dst->addrlen = sizeof(struct sockaddr_in6);

    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)(&dst->addr);
    sin6->sin6_family = BPF_CORE_READ(sk_c, skc_family);
    sin6->sin6_port = BPF_CORE_READ(sk_c, skc_dport);
    sin6->sin6_addr = BPF_CORE_READ(sk_c, skc_v6_daddr);

    return 0;
}

int copy_las_timestamp_from_current_task(struct elem_las_timestamp *dst)
{
    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct audit_stamp a_s = BPF_CORE_READ(current_task, audit_context, stamp);
    copy_las_timestamp_from_audit_context_timestamp(dst, &a_s);
    return 0;
}

int copy_las_timestamp_from_audit_context_timestamp(struct elem_las_timestamp *dst, struct audit_stamp *a_s)
{
    if (!dst || !a_s)
        return 0;

    unsigned int las_event_id = BPF_CORE_READ(a_s, serial);   
    struct timespec64 ctime = BPF_CORE_READ(a_s, ctime);
    dst->event_id = las_event_id;
    dst->tv_sec = ctime.tv_sec;
    dst->tv_nsec = ctime.tv_nsec;

    return 0;
}

int copy_net_ns_inum_from_current_task(inode_num_t *dst)
{
    if (!dst)
        return 0;
    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    inode_num_t net_ns_inum = BPF_CORE_READ(current_task, nsproxy, net_ns, ns).inum;
    *dst = net_ns_inum;
    return 0;
}

// int copy_sock_type_from_socket(short int *dst, struct socket *sock)
// {
//     if (sock != NULL && dst != NULL) {
//         *dst = BPF_CORE_READ(sock, type);
//     }
//     return 0;
// }