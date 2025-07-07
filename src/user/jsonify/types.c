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

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <stdlib.h>

#include "user/jsonify/types.h"


static int jsonify_types_write_record_type(struct json_buffer *s, const char *key, record_type_t val)
{
    return jsonify_core_write_int(s, key, val);
}

int jsonify_types_write_version(struct json_buffer *s, const char *key, const struct elem_version *version)
{
    const int max_size = 13;
    char local_val[max_size];
    memset(&local_val[0], 0, max_size);

    snprintf(&local_val[0], max_size, "%u.%u.%u", version->major, version->minor, version->patch);

    return jsonify_core_write_str(s, key, &local_val[0]);
}

static int jsonify_types_write_elem_sockaddr_raw(struct json_buffer *s, struct elem_sockaddr *sa)
{
    int total = 0;
    total += jsonify_core_write_bytes(s, "sockaddr", &(sa->addr[0]), sa->addrlen);
    total += jsonify_core_write_int(s, "sockaddr_len", sa->addrlen);
    return total;
}

static int jsonify_types_write_ip4_sockaddr_in(struct json_buffer *s, struct sockaddr_in *sa_in, byte_order_t byte_order)
{
    int total = 0;
    int port;
    char ip[INET_ADDRSTRLEN];

    port = sa_in->sin_port;
    switch (byte_order)
    {
        case BYTE_ORDER_NETWORK:
            port = ntohs(port);
            break;
        default:
            break;
    }
    if (!inet_ntop(AF_INET, &(sa_in->sin_addr), &ip[0], sizeof(ip)))
    {
        strncpy(&ip[0], "ERROR", sizeof("ERROR"));
        port = -1;
    }

    total += jsonify_core_write_uint(s, "family", sa_in->sin_family);
    total += jsonify_core_write_str(s, "ip", &ip[0]);
    total += jsonify_core_write_int(s, "port", port);
    return total;
}

static int jsonify_types_write_ip6_sockaddr_in(struct json_buffer *s, struct sockaddr_in6 *sa_in, byte_order_t byte_order)
{
    int total = 0;
    int port;
    char ip[INET6_ADDRSTRLEN];

    port = sa_in->sin6_port;
    switch (byte_order)
    {
        case BYTE_ORDER_NETWORK:
            port = ntohs(port);
            break;
        default:
            break;
    }
    if (!inet_ntop(AF_INET6, &(sa_in->sin6_addr), &ip[0], sizeof(ip)))
    {
        strncpy(&ip[0], "ERROR", sizeof("ERROR"));
        port = -1;
    }

    total += jsonify_core_write_uint(s, "family", sa_in->sin6_family);
    total += jsonify_core_write_str(s, "ip", &ip[0]);
    total += jsonify_core_write_int(s, "port", port);
    return total;
}

static int jsonify_types_write_sockaddr_un(struct json_buffer *s, struct sockaddr_un *sa_un)
{
    int path_start = 0;
    if (sa_un->sun_path[0])
    {
        path_start = 0;
    } else {
        path_start = 1;
    }
    int total = 0;
    total += jsonify_core_write_uint(s, "family", sa_un->sun_family);
    total += jsonify_core_write_str(s, "sun_path", &sa_un->sun_path[path_start]);
    return total;
}

static int jsonify_types_write_elem_sockaddr_generic(struct json_buffer *s, struct elem_sockaddr *e_sa)
{
    return jsonify_types_write_elem_sockaddr_raw(s, e_sa);
}

static int jsonify_types_write_sockaddr_nl(struct json_buffer *s, struct sockaddr_nl *sa_nl)
{
    int total = 0;
    total += jsonify_core_write_uint(s, "family", sa_nl->nl_family);
    total += jsonify_core_write_uint(s, "pid", sa_nl->nl_pid);
    total += jsonify_core_write_uint(s, "groups", sa_nl->nl_groups);
    return total;
}

static int jsonify_types_write_elem_timestamp(struct json_buffer *s, struct elem_timestamp *e_ts)
{
    int total = 0;
    total += jsonify_types_write_event_id(s, e_ts->event_id);
    return total;
}

int jsonify_types_write_fd(struct json_buffer *s, const char *key, int val)
{
    return jsonify_core_write_int(s, key, val);
}

int jsonify_types_write_return(struct json_buffer *s, const char *key, int val)
{
    return jsonify_core_write_int(s, key, val);
}

int jsonify_types_write_ssize(struct json_buffer *s, const char *key, ssize_t val)
{
    return jsonify_core_write_long(s, key, val);
}

int jsonify_types_write_pid(struct json_buffer *s, const char *key, pid_t val)
{
    return jsonify_core_write_int(s, key, val);
}

int jsonify_types_write_uid(struct json_buffer *s, const char *key, uid_t val)
{
    return jsonify_core_write_uint(s, key, val);
}

int jsonify_types_write_gid(struct json_buffer *s, const char *key, gid_t val)
{
    return jsonify_core_write_uint(s, key, val);
}

int jsonify_types_write_inode(struct json_buffer *s, const char *key, inode_num_t val)
{
    return jsonify_core_write_uint(s, key, val);
}

int jsonify_types_write_event_id(struct json_buffer *s, event_id_t val)
{
    return jsonify_core_write_ulong(s, "event_id", val);
}

int jsonify_types_write_sys_id(struct json_buffer *s, sys_id_t sys_id, int write_interpreted)
{
    int total = 0;
    total += jsonify_core_write_int(s, "sys_id", sys_id);
    if (write_interpreted)
    {
        total += jsonify_types_write_sys_name(s, sys_id);
    }
    return total;
}

int jsonify_types_write_sys_name(struct json_buffer *s, sys_id_t sys_id)
{
    char *sys_name;
    switch (sys_id)
    {
    case SYS_ID_FORK:
        sys_name = "fork";
        break;
    case SYS_ID_VFORK:
        sys_name = "vfork";
        break;
    case SYS_ID_CLONE:
        sys_name = "clone";
        break;
    case SYS_ID_SETNS:
        sys_name = "setns";
        break;
    case SYS_ID_UNSHARE:
        sys_name = "unshare";
        break;
    case SYS_ID_SENDTO:
        sys_name = "sendto";
        break;
    case SYS_ID_SENDMSG:
        sys_name = "sendmsg";
        break;
    case SYS_ID_RECVFROM:
        sys_name = "recvfrom";
        break;
    case SYS_ID_RECVMSG:
        sys_name = "recvmsg";
        break;
    case SYS_ID_ACCEPT:
        sys_name = "accept";
        break;
    case SYS_ID_ACCEPT4:
        sys_name = "accept4";
        break;
    default:
        sys_name = "UNKNOWN";
        break;
    }
    return jsonify_core_write_str(s, "sys_name", sys_name);
}

int jsonify_types_write_ip_family_name(struct json_buffer *s, char *key, int ip_family)
{
    char *ip_family_name;
    switch (ip_family)
    {
    case AF_INET:
        ip_family_name = "AF_INET";
        break;
    case AF_INET6:
        ip_family_name = "AF_INET6";
        break;
    default:
        ip_family_name = "UNKNOWN";
        break;
    }
    return jsonify_core_write_str(s, key, ip_family_name);
}

int jsonify_types_write_elem_las_timestamp(struct json_buffer *s, struct elem_las_timestamp *e_las_ts)
{
    char *s_child_buf = (char *)malloc(sizeof(char) * MAX_BUFFER_LEN);
    if (!s_child_buf)
        return 0;

    struct json_buffer s_child;
    jsonify_core_init(&s_child, s_child_buf, MAX_BUFFER_LEN);
    jsonify_core_open_obj(&s_child);

    jsonify_core_write_ulong(&s_child, "event_id", e_las_ts->event_id);
    jsonify_core_write_timespec64(&s_child, "time", e_las_ts->tv_sec, e_las_ts->tv_nsec);

    jsonify_core_close_obj(&s_child);

    int total = 0;

    char *s_child_buf_ptr;
    int s_child_buf_size;
    if (jsonify_core_get_internal_buf_ptr(&s_child, &s_child_buf_ptr, &s_child_buf_size) == 0)
    {
        total = jsonify_core_write_as_literal(s, "las_audit", s_child_buf_ptr);
    }

    free(s_child_buf);
    return total;
}

int jsonify_types_write_elem_sockaddr(struct json_buffer *s, const char *key, struct elem_sockaddr *e_sa, int write_interpreted)
{
    char *s_child_buf = (char *)malloc(sizeof(char) * MAX_BUFFER_LEN);
    if (!s_child_buf)
        return 0;

    struct json_buffer s_child;
    jsonify_core_init(&s_child, s_child_buf, MAX_BUFFER_LEN);
    jsonify_core_open_obj(&s_child);

    if (!write_interpreted)
    {
        jsonify_types_write_elem_sockaddr_generic(&s_child, e_sa);
    }else{
        struct sockaddr *sa = (struct sockaddr *)(e_sa->addr);
        switch (sa->sa_family)
        {
            case AF_INET:
                jsonify_types_write_ip4_sockaddr_in(&s_child, (struct sockaddr_in *)sa, e_sa->byte_order);
                break;
            case AF_INET6:
                jsonify_types_write_ip6_sockaddr_in(&s_child, (struct sockaddr_in6 *)sa, e_sa->byte_order);
                break;
            case AF_UNIX:
                jsonify_types_write_sockaddr_un(&s_child, (struct sockaddr_un *)sa);
                break;
            case AF_NETLINK:
                jsonify_types_write_sockaddr_nl(&s_child, (struct sockaddr_nl *)sa);
                break;
            default:
                jsonify_types_write_elem_sockaddr_generic(&s_child, e_sa);
                break;
        }
    }

    jsonify_core_close_obj(&s_child);

    int total = 0;

    char *s_child_buf_ptr;
    int s_child_buf_size;
    if (jsonify_core_get_internal_buf_ptr(&s_child, &s_child_buf_ptr, &s_child_buf_size) == 0)
    {
        total = jsonify_core_write_as_literal(s, key, s_child_buf_ptr);
    }

    free(s_child_buf);
    return total;
}

int jsonify_types_write_common(
    struct json_buffer *s, struct elem_common *e_common, 
    struct elem_timestamp *e_ts, char *record_type_name
)
{
    int total = 0;
    total += jsonify_core_write_str(s, "record_name", record_type_name);
    total += jsonify_types_write_record_type(s, "record_type", e_common->record_type);
    total += jsonify_types_write_version(s, "record_version", &e_common->version);
    total += jsonify_types_write_elem_timestamp(s, e_ts);
#ifdef INCLUDE_TASK_CTX_ID
    total += jsonify_core_write_ulonglong(s, "task_ctx_id", e_common->task_ctx_id);
#endif
    return total;
}
