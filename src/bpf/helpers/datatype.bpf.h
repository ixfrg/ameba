#pragma once

/*

    A module for defining helper functions to initialize and zero-out data types like the record type.

*/

#include "common/vmlinux.h"
#include "common/types.h"


/*
    Initialize e_version to the value of the current version.

    Return:
        0 => Always
*/
int datatype_init_elem_version(struct elem_version *e_version);

/*
    Initialize e_common and child structs to default values.

    Return:
        0 => Always
*/
int datatype_init_elem_common(struct elem_common *e_common, record_type_t record_type);

/*
    Initialize e_ts with the given event_id.

    Return:
        0 => Always
*/
int datatype_init_elem_timestamp(struct elem_timestamp *e_ts, event_id_t event_id);

/*
    Initialize e_sockaddr with the given addrlen and byte_order.

    Return:
        0 => Always
*/
int datatype_init_elem_sockaddr(struct elem_sockaddr *e_sockaddr, socklen_t addrlen, byte_order_t byte_order);

/*
    Zero-out e_sockaddr.

    Return:
        0 => Always
*/
int datatype_zero_out_elem_sockaddr(struct elem_sockaddr *e_sockaddr);

/*
    Initialize r_new_process with the given arguments after r_new_process.

    Return:
        0 => Always
*/
int datatype_init_record_new_process(struct record_new_process *r_new_process, event_id_t event_id, pid_t pid, pid_t ppid, sys_id_t sys_id);

/*
    Initialize r_c with the given arguments after r_c.

    Return:
        0 => Always
*/
int datatype_init_record_cred(struct record_cred *r_c, event_id_t event_id, pid_t pid, sys_id_t sys_id);

/*
    Initialize r_namespace with the given arguments after r_namespace.

    Return:
        0 => Always
*/
int datatype_init_record_namespace(struct record_namespace *r_namespace, event_id_t event_id, pid_t pid, sys_id_t sys_id);

/*
    Initialize r_connect with the given arguments after r_connect.

    Return:
        0 => Always
*/
int datatype_init_record_connect(struct record_connect *r_connect, pid_t pid, int fd, int ret);

/*
    Zero-out r_connect.

    Return:
        0 => Always
*/
int datatype_zero_out_record_connect(struct record_connect *r_connect);

/*
    Initialize r_accept with the given arguments after r_accept.

    Return:
        0 => Always
*/
int datatype_init_record_accept(struct record_accept *r_accept, pid_t pid, int fd);

/*
    Zero-out r_accept and set sys_id.

    Return:
        0 => Always
*/
int datatype_zero_out_record_accept(struct record_accept *r_accept, sys_id_t sys_id);

/*
    Initialize r_accept and set fd.

    Return:
        0 => Always
*/
int datatype_init_fd_record_accept(struct record_accept *r_accept, int fd);

/*
    Initialize r_send_recv with the given arguments after r_send_recv.

    Return:
        0 => Always
*/
int datatype_init_record_send_recv(struct record_send_recv *r_send_recv, pid_t pid, int fd, ssize_t ret);

/*
    Zero-out r_send_recv.

    Return:
        0 => Always
*/
int datatype_zero_out_record_send_recv(struct record_send_recv *r_send_recv);

/*
    Initialize r_bind with the given arguments after r_bind.

    Return:
        0 => Always
*/
int datatype_init_record_bind(struct record_bind *r_bind, pid_t pid, int fd);

/*
    Zero-out r_bind.

    Return:
        0 => Always
*/
int datatype_zero_out_record_bind(struct record_bind *r_bind);

/*
    Initialize r_kill with the given arguments after r_kill.

    Return:
        0 => Always
*/
int datatype_init_record_kill(struct record_kill *r_kill, pid_t acting_pid, pid_t target_pid, int sig);

/*
    Initialize r_ale with the given arguments after r_ale.

    Return:
        0 => Always
*/
int datatype_init_record_audit_log_exit(struct record_audit_log_exit *r_ale, pid_t pid, event_id_t event_id, int syscall_number);