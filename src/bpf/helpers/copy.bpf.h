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
// int copy_sock_type_from_socket(short int *dst, struct socket *sock);