#pragma once

#include "common/vmlinux.h"

#include "common/types.h"


int accept_storage_insert_local_fd(struct record_accept *map_val);
int accept_storage_insert_remote_fd(struct record_accept *map_val);
int accept_storage_set_local_fd_saddrs(struct elem_sockaddr *local, struct elem_sockaddr *remote);
int accept_storage_set_remote_fd_saddrs(struct elem_sockaddr *local, struct elem_sockaddr *remote);
int accept_storage_set_local_fd_props_on_sys_exit(pid_t pid, event_id_t event_id);
int accept_storage_set_remote_fd_props_on_sys_exit(pid_t pid, int ret_fd, event_id_t event_id);
int accept_storage_delete_local_fd(void);
int accept_storage_delete_remote_fd(void);
int accept_storage_delete_both_fds(void);
int accept_storage_output_local_fd(void);
int accept_storage_output_remote_fd(void);
