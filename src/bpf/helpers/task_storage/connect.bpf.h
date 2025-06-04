#pragma once

#include "common/vmlinux.h"

#include "common/types.h"


int task_storage_connect_insert(struct record_connect *map_val);
int task_storage_connect_delete(void);
int task_storage_connect_set_props_on_sys_exit(pid_t pid, int fd, int ret, event_id_t event_id);
int task_storage_connect_set_local(struct elem_sockaddr *local);
int task_storage_connect_set_remote(struct elem_sockaddr *remote);
int task_storage_connect_output(void);