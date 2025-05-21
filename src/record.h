#ifndef __RECORD_H
#define __RECORD_H

#include "constants.h"

#define RECORD_TYPE_PROCESS 1
#define RECORD_TYPE_CRED 2
#define RECORD_TYPE_NAMESPACE 3
#define RECORD_TYPE_CONNECT 4

#define SYS_ID_FORK 1
#define SYS_ID_VFORK 2
#define SYS_ID_CLONE 3
#define SYS_ID_SETNS 4
#define SYS_ID_UNSHARE 5

#define RECORD_SIZE_PROCESS sizeof(struct record_process)
#define RECORD_SIZE_CRED sizeof(struct record_cred)
#define RECORD_SIZE_NAMESPACE sizeof(struct record_namespace)
#define RECORD_SIZE_CONNECT sizeof(struct record_connect)


/*
Notes:
1. 'record_type_id' is the first element in all record structs.
*/


struct elem_common
{
    int record_type_id;
    unsigned long event_id;
};

struct elem_sockaddr
{
    unsigned char addr[SOCKADDR_MAX_SIZE];
    int addrlen; // socklen_t addrlen;
};

struct record_process
{
    struct elem_common e_common;
    pid_t pid;
    pid_t ppid;
    char comm[COMM_MAX_SIZE];
};

struct record_cred
{
    struct elem_common e_common;
    pid_t pid;
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
    pid_t pid;
    unsigned int ipc;
    unsigned int mnt;
    unsigned int pid_children;
    unsigned int net;
    unsigned int cgroup;
};

struct record_connect
{
    struct elem_common e_common;
    pid_t pid;
    int fd;
    int ret;
    struct elem_sockaddr local;
    struct elem_sockaddr remote;
};

#endif
