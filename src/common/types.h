#pragma once


#include "common/constants.h"


// scalar typedefs
typedef int magic_t;
typedef unsigned long event_id_t;
typedef unsigned int inode_num_t;
typedef unsigned short major_t;
typedef unsigned char minor_t;
typedef unsigned char patch_t;
typedef unsigned int socklen_t;


// enums
typedef enum {
    RECORD_TYPE_NEW_PROCESS = 1,
    RECORD_TYPE_CRED,
    RECORD_TYPE_NAMESPACE,
    RECORD_TYPE_CONNECT,
    RECORD_TYPE_ACCEPT,
    RECORD_TYPE_SEND
} record_type_t;

typedef enum {
    SYS_ID_FORK = 1,
    SYS_ID_VFORK,
    SYS_ID_CLONE,
    SYS_ID_SETNS,
    SYS_ID_UNSHARE,
    SYS_ID_SENDTO,
    SYS_ID_SENDMSG
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
};

struct elem_timestamp
{
    event_id_t event_id;
};

struct elem_sockaddr
{
    unsigned char addr[SOCKADDR_MAX_SIZE];
    socklen_t addrlen;
    byte_order_t byte_order;
};

struct record_new_process
{
    struct elem_common e_common;
    struct elem_timestamp e_ts;
    pid_t ppid;
    pid_t pid;
    sys_id_t sys_id;
    // char comm[COMM_MAX_SIZE];
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
    struct elem_sockaddr local;
    struct elem_sockaddr remote;
};

struct record_accept
{
    struct elem_common e_common;
    struct elem_timestamp e_ts;
    pid_t pid;
    int fd;
    struct elem_sockaddr local;
    struct elem_sockaddr remote;
};

struct record_send
{
    struct elem_common e_common;
    struct elem_timestamp e_ts;
    pid_t pid;
    sys_id_t sys_id;
    int fd;
    ssize_t ret;
    struct elem_sockaddr local;
    struct elem_sockaddr remote;
};

typedef enum {
    RECORD_SIZE_NEW_PROCESS = sizeof(struct record_new_process),
    RECORD_SIZE_CRED = sizeof(struct record_cred),
    RECORD_SIZE_NAMESPACE = sizeof(struct record_namespace),
    RECORD_SIZE_CONNECT = sizeof(struct record_connect),
    RECORD_SIZE_ACCEPT = sizeof(struct record_accept),
    RECORD_SIZE_SEND = sizeof(struct record_send)
} record_size_t;