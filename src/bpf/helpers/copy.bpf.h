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

#pragma once

/*

    A module for defining helper functions to copy data from kernel/user space.

*/

#include "common/vmlinux.h"
#include "common/types.h"

/*
    Copy equivalent of source sockaddr_in (ip4) from sk_c into dst.

    Return:
        0 => Always
*/
int copy_sockaddr_in_local_from_skc(struct elem_sockaddr *dst, struct sock_common *sk_c);

/*
    Copy equivalent of destination sockaddr_in (ip4) from sk_c into dst.

    Return:
        0 => Always
*/
int copy_sockaddr_in_remote_from_skc(struct elem_sockaddr *dst, struct sock_common *sk_c);

/*
    Copy equivalent of source sockaddr_in (ip6) from sk_c into dst.

    Return:
        0 => Always
*/
int copy_sockaddr_in6_local_from_skc(struct elem_sockaddr *dst, struct sock_common *sk_c);

/*
    Copy equivalent of destination sockaddr_in (ip6) from sk_c into dst.

    Return:
        0 => Always
*/
int copy_sockaddr_in6_remote_from_skc(struct elem_sockaddr *dst, struct sock_common *sk_c);

/*
    Copy event id and timestamp from current task's audit context's audit_stamp into dst.

    Return:
        0 => Always
*/
int copy_las_timestamp_from_current_task(struct elem_las_timestamp *dst);

/*
    Copy event id and timestamp from the given audit_stamp into dst.

    Return:
        0 => Always
*/
int copy_las_timestamp_from_audit_context_timestamp(struct elem_las_timestamp *dst, struct audit_stamp *a_s);

/*
    Copy current task's network namespace inode number into dst.

    Return:
        0 => Always
*/
int copy_net_ns_inum_from_current_task(inode_num_t *dst);