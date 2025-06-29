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
#include "bpf/events/bind/storage.bpf.h"


static int common_sock_bind(
    struct socket *sock,
    int err
)
{
    if (err)
        return 0;

    if (!sock)
        return 0;

    const struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    const pid_t pid = BPF_CORE_READ(current_task, pid);

    struct record_bind r_bind;
    datatype_init_record_bind(&r_bind, pid, -1);

    r_bind.sock_type = (short int)BPF_CORE_READ(sock, type);
    copy_net_ns_inum_from_current_task(&(r_bind.ns_net));

    bind_storage_insert(&r_bind);

    return 0;
}


int AMEBA_HOOK(
    "fexit/unix_bind",
    fexit__unix_bind,
    RECORD_TYPE_BIND,
    struct socket *sock, 
    struct sockaddr *uaddr, 
    int addr_len,
    int ret
)
{
    return common_sock_bind(sock, ret);
}


int AMEBA_HOOK(
    "fexit/inet_bind",
    fexit__inet_bind,
    RECORD_TYPE_BIND,
    struct socket *sock, 
    struct sockaddr *uaddr, 
    int addr_len,
    int ret
)
{
    return common_sock_bind(sock, ret);
}


int AMEBA_HOOK(
    "fexit/inet6_bind",
    fexit__inet6_bind,
    RECORD_TYPE_BIND,
    struct socket *sock, 
    struct sockaddr *uaddr, 
    int addr_len,
    int ret
)
{
    return common_sock_bind(sock, ret);
}


int AMEBA_HOOK(
    "fexit/__sys_bind",
    fexit__sys_bind,
    RECORD_TYPE_BIND,
    int fd,
    struct sockaddr *sockaddr,
    int addrlen,
    int ret
)
{
    if (ret == -1)
        return 0;

    struct elem_sockaddr local_sa;
    local_sa.byte_order = BYTE_ORDER_NETWORK;
    local_sa.addrlen = addrlen & (SOCKADDR_MAX_SIZE - 1);
    bpf_probe_read_user(&(local_sa.addr[0]), local_sa.addrlen, sockaddr);

    bind_storage_set(fd, event_id_increment(), &local_sa);

    bind_storage_output();

    bind_storage_delete();

    return 0;
}