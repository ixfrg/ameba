#pragma once


#include "common/vmlinux.h"
#include "common/types.h"


int recordhelper_init_elem_version(struct elem_version *e_version);
int recordhelper_init_elem_common(struct elem_common *e_common, record_type_t record_type);
int recordhelper_init_elem_timestamp(struct elem_timestamp *e_ts, event_id_t event_id);
int recordhelper_init_elem_sockaddr(struct elem_sockaddr *e_sockaddr, socklen_t addrlen, byte_order_t byte_order);
int recordhelper_zero_out_elem_sockaddr(struct elem_sockaddr *e_sockaddr);
int recordhelper_init_record_new_process(struct record_new_process *r_new_process, event_id_t event_id, pid_t pid, pid_t ppid, sys_id_t sys_id);
int recordhelper_init_record_cred(struct record_cred *r_c, event_id_t event_id, pid_t pid, sys_id_t sys_id);
int recordhelper_init_record_namespace(struct record_namespace *r_namespace, event_id_t event_id, pid_t pid, sys_id_t sys_id);
int recordhelper_init_record_connect(struct record_connect *r_connect, pid_t pid, int fd, int ret);
int recordhelper_zero_out_record_connect(struct record_connect *r_connect);
int recordhelper_init_record_accept(struct record_accept *r_accept, pid_t pid, int fd);
int recordhelper_zero_out_record_accept(struct record_accept *r_accept);
int recordhelper_init_record_send_recv(struct record_send_recv *r_send_recv, pid_t pid, int fd, ssize_t ret);
int recordhelper_zero_out_record_send_recv(struct record_send_recv *r_send_recv);
int recordhelper_init_record_bind(struct record_bind *r_bind, pid_t pid, int fd);
int recordhelper_zero_out_record_bind(struct record_bind *r_bind);