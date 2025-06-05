#pragma once

#include "common/vmlinux.h"

#include "common/types.h"


int send_recv_storage_insert(struct record_send_recv *map_val);
int send_recv_storage_delete(void);
int send_recv_storage_set_saddrs(short int sock_type, struct elem_sockaddr *local, struct elem_sockaddr *remote);
int send_recv_storage_set_props_on_sys_exit(pid_t pid, int fd, ssize_t ret, event_id_t event_id);
int send_recv_storage_output(void);