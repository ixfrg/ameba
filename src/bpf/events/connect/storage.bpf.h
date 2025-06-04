#pragma once

#include "common/vmlinux.h"

#include "common/types.h"


int connect_storage_insert(struct record_connect *map_val);
int connect_storage_delete(void);
int connect_storage_set_props_on_sys_exit(pid_t pid, int fd, int ret, event_id_t event_id);
int connect_storage_set_local(struct elem_sockaddr *local);
int connect_storage_set_remote(struct elem_sockaddr *remote);
int connect_storage_output(void);