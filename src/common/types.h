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

    A module for defining common types (i.e. records, and etc.)
    used by BPF and user programs.

*/

#include "common/constants.h"
#include "common/kernel_constants.h"


// scalar typedefs
typedef int magic_t;
typedef unsigned long event_id_t;
typedef unsigned int inode_num_t;
typedef unsigned short major_t;
typedef unsigned char minor_t;
typedef unsigned char patch_t;
typedef unsigned int socklen_t;
typedef unsigned long long task_ctx_id_t;


// enums
typedef enum {
    RECORD_TYPE_NEW_PROCESS = 1,
    RECORD_TYPE_CRED,
    RECORD_TYPE_NAMESPACE,
    RECORD_TYPE_CONNECT,
    RECORD_TYPE_ACCEPT,
    RECORD_TYPE_SEND_RECV,
    RECORD_TYPE_BIND,
    RECORD_TYPE_KILL,
    RECORD_TYPE_AUDIT_LOG_EXIT
} record_type_t;

typedef enum {
    SYS_ID_FORK = 1,
    SYS_ID_VFORK,
    SYS_ID_CLONE,
    SYS_ID_SETNS,
    SYS_ID_UNSHARE,
    SYS_ID_SENDTO,
    SYS_ID_SENDMSG,
    SYS_ID_RECVFROM,
    SYS_ID_RECVMSG,
    SYS_ID_ACCEPT,
    SYS_ID_ACCEPT4
} sys_id_t;

typedef enum {
    BYTE_ORDER_NETWORK = 1,
    BYTE_ORDER_HOST
} byte_order_t;


// structs

/*
Notes:
1. 'elem_common' is the first element in all record_* structs.
2. 'magic' is the first integer in 'elem_common'.
3. 'record_type_id' is the second integer in 'elem_common'.

The above 3 points ensure a uniform way of identifying the records
belonging to ameba.

A. All record structs must have the following two structs
    i. struct elem_common e_common;
    ii. struct elem_timestamp e_ts;
*/

struct elem_version
{
    major_t major;
    minor_t minor;
    patch_t patch;
};

struct elem_common
{
    magic_t magic;
    record_type_t record_type;
    struct elem_version version;
#ifdef INCLUDE_TASK_CTX_ID
    task_ctx_id_t task_ctx_id;
#endif
};

struct elem_timestamp
{
    event_id_t event_id;
};

struct elem_sockaddr
{
    unsigned char addr[AMEBA_SOCKADDR_MAX_SIZE];
    socklen_t addrlen;
    byte_order_t byte_order;
};

struct elem_las_timestamp
{
    unsigned long event_id;
    long long tv_sec;
	long tv_nsec;
};

struct record_new_process
{
    struct elem_common e_common;
    struct elem_timestamp e_ts;
    pid_t ppid;
    pid_t pid;
    sys_id_t sys_id;
    char comm[AMEBA_COMM_MAX_SIZE];
    // struct elem_las_timestamp e_las_ts;
};

struct record_cred
{
    struct elem_common e_common;
    struct elem_timestamp e_ts;
    pid_t pid;
    sys_id_t sys_id;
    uid_t uid;
    uid_t euid;
    uid_t suid;
    uid_t fsuid;
    gid_t gid;
    gid_t egid;
    gid_t sgid;
    gid_t fsgid;
};

struct record_namespace
{
    struct elem_common e_common;
    struct elem_timestamp e_ts;
    pid_t pid;
    sys_id_t sys_id;
    inode_num_t ns_ipc;
    inode_num_t ns_mnt;
    inode_num_t ns_pid;
    inode_num_t ns_pid_children;
    inode_num_t ns_net;
    inode_num_t ns_cgroup;
    inode_num_t ns_usr;
};

struct record_connect
{
    struct elem_common e_common;
    struct elem_timestamp e_ts;
    pid_t pid;
    int fd;
    int ret;
    inode_num_t ns_net;
    short int sock_type;
    struct elem_sockaddr local;
    struct elem_sockaddr remote;
};

struct record_accept
{
    struct elem_common e_common;
    struct elem_timestamp e_ts;
    pid_t pid;
    sys_id_t sys_id;
    int fd;
    int ret;
    inode_num_t ns_net;
    short int sock_type;
    struct elem_sockaddr local;
    struct elem_sockaddr remote;
};

struct record_send_recv
{
    struct elem_common e_common;
    struct elem_timestamp e_ts;
    pid_t pid;
    sys_id_t sys_id;
    int fd;
    ssize_t ret;
    inode_num_t ns_net;
    short int sock_type;
    struct elem_sockaddr local;
    struct elem_sockaddr remote;
};

struct record_bind
{
    struct elem_common e_common;
    struct elem_timestamp e_ts;
    pid_t pid;
    int fd;
    inode_num_t ns_net;
    short int sock_type;
    struct elem_sockaddr local;
    // struct elem_sockaddr remote;
};

struct record_kill
{
    struct elem_common e_common;
    struct elem_timestamp e_ts;
    pid_t acting_pid;
    int sig;
    pid_t target_pid;
    int ret;
};

struct record_audit_log_exit
{
    struct elem_common e_common;
    struct elem_timestamp e_ts;
    pid_t pid;
    int syscall_number;
    long int ret;
    struct elem_las_timestamp e_las_ts;
};

typedef enum {
    RECORD_SIZE_NEW_PROCESS = sizeof(struct record_new_process),
    RECORD_SIZE_CRED = sizeof(struct record_cred),
    RECORD_SIZE_NAMESPACE = sizeof(struct record_namespace),
    RECORD_SIZE_CONNECT = sizeof(struct record_connect),
    RECORD_SIZE_ACCEPT = sizeof(struct record_accept),
    RECORD_SIZE_SEND_RECV = sizeof(struct record_send_recv),
    RECORD_SIZE_BIND = sizeof(struct record_bind),
    RECORD_SIZE_KILL = sizeof(struct record_kill),
    RECORD_SIZE_AUDIT_LOG_EXIT = sizeof(struct record_audit_log_exit)
} record_size_t;